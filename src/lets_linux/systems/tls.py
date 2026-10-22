"""Simulated X.509: certificates, keys, signing requests, trust stores and verification.

A certificate is a PEM block whose base64 body carries the fields the simulation needs
(subject, issuer, serial, validity, subject alternative names, the key it certifies, the key
that signed it, CA flag) behind a DER-like prefix — it looks like a certificate, and the
simulated openssl, curl, wget and nginx read it. Nothing is cryptographically signed: "B is
signed by A" means B names A's key as its issuer key. Verification follows OpenSSL: build the
chain from the certificates the server sent and the trusted anchors, then check validity
periods; host names are matched against the subjectAltName entries only (as current clients
do). Error codes and messages are OpenSSL's.

The world's certificate authorities (a public root and issuing CA, Example Corp's internal
root) are generated deterministically; HTTPS services of the simulated network carry a chain
described by their ``tls`` table (see world.py).
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

from lets_linux.systems.clock import DEFAULT_EPOCH

if TYPE_CHECKING:
    from lets_linux.systems.machine import Machine

DAY = 86400.0
#: makes the base64 body start with "MII…" like a real DER certificate
_DER = b"0\x82\x05\x1fSIMX509:"

CERT, KEY, CSR = "CERTIFICATE", "PRIVATE KEY", "CERTIFICATE REQUEST"

MESSAGES = {
    0: "ok",
    2: "unable to get issuer certificate",
    7: "certificate signature failure",
    9: "certificate is not yet valid",
    10: "certificate has expired",
    18: "self-signed certificate",
    19: "self-signed certificate in certificate chain",
    20: "unable to get local issuer certificate",
    21: "unable to verify the first certificate",
    24: "invalid CA certificate",
    62: "hostname mismatch",
}


# ------------------------------------------------------------------ PEM


def to_pem(kind: str, data: dict[str, Any]) -> str:
    raw = _DER + json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    body = base64.b64encode(raw).decode()
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return f"-----BEGIN {kind}-----\n" + "\n".join(lines) + f"\n-----END {kind}-----\n"


_BLOCK = re.compile(r"-----BEGIN ([A-Z ]+)-----\s*(.*?)\s*-----END \1-----", re.S)


def pem_blocks(text: str) -> list[tuple[str, dict[str, Any] | None]]:
    """Every PEM block in TEXT: (kind, its fields — None when it is not a simulated object)."""
    out: list[tuple[str, dict[str, Any] | None]] = []
    for m in _BLOCK.finditer(text):
        kind = m.group(1).replace("RSA ", "").replace("EC ", "")
        try:
            raw = base64.b64decode("".join(m.group(2).split()), validate=True)
            data = json.loads(raw[len(_DER) :]) if raw.startswith(_DER) else None
        except (ValueError, json.JSONDecodeError):
            data = None
        out.append((kind, data))
    return out


# ------------------------------------------------------------------ objects


def _fmt_name(name: dict[str, str], sep: str = ", ") -> str:
    order = ["C", "ST", "L", "O", "OU", "CN"]
    keys = [k for k in order if k in name] + [k for k in name if k not in order]
    return sep.join(f"{k} = {name[k]}" for k in keys)


@dataclass
class PrivateKey:
    key_id: str
    key_type: str = "RSA"  # RSA, EC, ED25519
    bits: int = 2048

    def to_pem(self) -> str:
        return to_pem(KEY, {"key": self.key_id, "type": self.key_type, "bits": self.bits})

    @classmethod
    def from_data(cls, d: dict[str, Any]) -> PrivateKey:
        return cls(str(d["key"]), str(d.get("type", "RSA")), int(d.get("bits", 2048)))

    @property
    def modulus(self) -> str:
        return hashlib.sha512(self.key_id.encode()).hexdigest().upper()[: self.bits // 4]


@dataclass
class Certificate:
    subject: dict[str, str]
    issuer: dict[str, str]
    serial: str
    not_before: float
    not_after: float
    key_id: str
    issuer_key_id: str
    ca: bool = False
    sans: list[str] = field(default_factory=list)  # "DNS:name", "IP:addr"
    key_type: str = "RSA"
    bits: int = 2048

    def to_data(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_data(cls, d: dict[str, Any]) -> Certificate:
        fields = {k: d[k] for k in cls.__dataclass_fields__ if k in d}
        return cls(**fields)

    def to_pem(self) -> str:
        return to_pem(CERT, self.to_data())

    @property
    def self_signed(self) -> bool:
        return self.key_id == self.issuer_key_id

    @property
    def cn(self) -> str:
        return self.subject.get("CN", "")

    def subject_line(self, sep: str = ", ") -> str:
        return _fmt_name(self.subject, sep)

    def issuer_line(self, sep: str = ", ") -> str:
        return _fmt_name(self.issuer, sep)

    def fingerprint(self, algorithm: str = "sha256") -> str:
        digest = (
            hashlib.new(algorithm, json.dumps(self.to_data(), sort_keys=True).encode())
            .hexdigest()
            .upper()
        )
        return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))

    def dns_names(self) -> list[str]:
        return [s[4:] for s in self.sans if s.startswith("DNS:")]

    def matches(self, host: str) -> bool:
        """Does the certificate cover HOST (subjectAltName only, one-label wildcards)?"""
        host = host.lower().rstrip(".")
        for san in self.sans:
            kind, _, value = san.partition(":")
            value = value.lower()
            if kind == "IP" and value == host:
                return True
            if kind != "DNS":
                continue
            if value == host:
                return True
            if value.startswith("*.") and "." in host and host.split(".", 1)[1] == value[2:]:
                return True
        return False


@dataclass
class SigningRequest:
    subject: dict[str, str]
    key_id: str
    sans: list[str] = field(default_factory=list)
    key_type: str = "RSA"
    bits: int = 2048

    def to_pem(self) -> str:
        return to_pem(CSR, asdict(self))

    @classmethod
    def from_data(cls, d: dict[str, Any]) -> SigningRequest:
        return cls(dict(d["subject"]), str(d["key_id"]), list(d.get("sans", [])), str(d.get("key_type", "RSA")),
                   int(d.get("bits", 2048)))  # fmt: skip


def certificates(text: str) -> list[Certificate]:
    return [
        Certificate.from_data(d) for kind, d in pem_blocks(text) if kind == CERT and d is not None
    ]


def parse_subject(text: str) -> dict[str, str]:
    """'/C=US/O=Example Corp/CN=api.example.lan' (openssl -subj) → fields."""
    out: dict[str, str] = {}
    for part in [p for p in re.split(r"(?<!\\)/", text) if p]:
        key, sep, value = part.partition("=")
        if not sep or not key.strip():
            raise ValueError(f"Hit end of string before finding the '=' in '{part}'")
        out[key.strip()] = value.replace("\\/", "/")
    return out


def parse_sans(text: str) -> list[str]:
    """'subjectAltName=DNS:a,DNS:b,IP:10.0.0.1' or 'DNS:a, DNS:b' → entries."""
    value = text.split("=", 1)[1] if text.strip().startswith("subjectAltName") else text
    out = []
    for item in value.split(","):
        kind, _, name = item.strip().partition(":")
        if kind.upper() in ("DNS", "IP") and name:
            out.append(f"{kind.upper()}:{name.strip()}")
    return out


def key_id_for(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:40]


def serial_for(seed: str) -> str:
    return hashlib.md5(seed.encode()).hexdigest()[:32].upper()  # noqa: S324 - an identifier, not security


def issue(subject: dict[str, str], key_id: str, issuer: Certificate | None, issuer_key: str, *, not_before: float,
          days: float, ca: bool = False, sans: list[str] | None = None, serial: str = "",
          bits: int = 2048, key_type: str = "RSA") -> Certificate:  # fmt: skip
    """A certificate for KEY_ID signed with ISSUER_KEY (ISSUER None: self-signed)."""
    return Certificate(
        subject=dict(subject),
        issuer=dict(issuer.subject if issuer is not None else subject),
        serial=serial or serial_for(f"{subject}{key_id}{not_before}"),
        not_before=not_before,
        not_after=not_before + days * DAY,
        key_id=key_id,
        issuer_key_id=issuer_key if issuer is not None else key_id,
        ca=ca,
        sans=list(sans or []),
        key_type=key_type,
        bits=bits,
    )


# ------------------------------------------------------------------ the world's authorities


def _date(y: int, m: int, d: int) -> float:
    return _dt.datetime(y, m, d, tzinfo=_dt.UTC).timestamp()


@dataclass
class Authority:
    cert: Certificate
    key: PrivateKey
    #: shipped in the distributions' trust stores (ca-certificates)
    public: bool
    filename: str


def _authorities() -> dict[str, Authority]:
    out: dict[str, Authority] = {}

    def root(
        name: str, subject: dict[str, str], start: float, years: int, public: bool, filename: str
    ) -> None:
        key = PrivateKey(key_id_for(name), "RSA", 4096)
        out[name] = Authority(issue(subject, key.key_id, None, "", not_before=start, days=365 * years, ca=True,
                                    bits=4096), key, public, filename)  # fmt: skip

    root("public-root", {"C": "US", "O": "Simulated Trust Services", "CN": "Simulated Root X1"},
         _date(2015, 6, 4), 20, True, "Simulated_Root_X1.crt")  # fmt: skip
    root("global-root", {"C": "BE", "O": "Simulated Global Trust", "CN": "Simulated Global Root G2"},
         _date(2017, 3, 1), 21, True, "Simulated_Global_Root_G2.crt")  # fmt: skip
    root("corp-root", {"C": "DE", "O": "Example Corp", "CN": "Example Corp Root CA"},
         _date(2023, 1, 10), 10, False, "example-corp-root.crt")  # fmt: skip
    root(
        "lab-ca",
        {"O": "Example Corp Lab", "CN": "Example Lab CA"},
        _date(2025, 1, 6),
        10,
        False,
        "example-lab-ca.crt",
    )
    issuer = out["public-root"]
    key = PrivateKey(key_id_for("public-ca"), "RSA", 2048)
    out["public-ca"] = Authority(
        issue({"C": "US", "O": "Simulated Trust Services", "CN": "Simulated TLS R10"}, key.key_id, issuer.cert,
              issuer.key.key_id, not_before=_date(2024, 3, 13), days=1095, ca=True),
        key, False, "Simulated_TLS_R10.crt",
    )  # fmt: skip
    return out


AUTHORITIES = _authorities()


def service_chain(
    peer_name: str, port: int, spec: dict[str, Any], names: list[str]
) -> list[Certificate]:
    """The chain an HTTPS service of the simulated network sends, from its ``tls`` table:
    ca (public | corp | self), names, not_before_days (relative to the default start date),
    days, chain (False: the server forgets to send its intermediate certificate)."""
    ca = str(spec.get("ca", "public"))
    names = [str(n) for n in spec.get("names", names)] or [peer_name]
    start = DEFAULT_EPOCH + float(spec.get("not_before_days", -45)) * DAY
    days = float(spec.get("days", 90))
    subject = {"CN": str(spec.get("cn", names[0]))}
    key = key_id_for(f"{peer_name}:{port}")
    sans = [f"DNS:{n}" if not re.fullmatch(r"[\d.]+", n) else f"IP:{n}" for n in names]
    if ca == "self":
        subject = {"C": "DE", "O": str(spec.get("org", "Example Corp")), **subject}
        return [issue(subject, key, None, "", not_before=start, days=days, sans=sans)]
    authority = AUTHORITIES["public-ca" if ca == "public" else "corp-root"]
    leaf = issue(
        subject, key, authority.cert, authority.key.key_id, not_before=start, days=days, sans=sans
    )
    if ca == "public" and spec.get("chain", True):
        return [leaf, authority.cert]
    return [leaf]


# ------------------------------------------------------------------ trust stores


def bundle_path(machine: Machine) -> str:
    return (
        "/etc/pki/tls/certs/ca-bundle.crt"
        if machine.profile.family == "fedora"
        else "/etc/ssl/certs/ca-certificates.crt"
    )


def trusted(
    machine: Machine, *, cafile: str | None = None, capath: str | None = None
) -> list[Certificate]:
    """The trust anchors a client uses: the system bundle, or CAFILE/CAPATH instead."""
    from lets_linux.filesystem import FsError

    ops = machine.root_ops
    texts: list[str] = []
    try:
        if cafile is not None:
            texts.append(ops.read_text(cafile))
        elif capath is not None:
            texts += [ops.read_text(f"{capath}/{n}") for n in sorted(ops.listdir(capath))
                      if ops.exists(f"{capath}/{n}") and not ops.stat(f"{capath}/{n}").is_dir]  # fmt: skip
        else:
            texts.append(ops.read_text(bundle_path(machine)))
    except FsError:
        return []
    return [c for t in texts for c in certificates(t)]


@dataclass
class Verification:
    code: int
    depth: int = 0
    path: list[Certificate] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.code == 0

    @property
    def message(self) -> str:
        return MESSAGES.get(self.code, "unknown error")


def verify(chain: list[Certificate], anchors: list[Certificate], now: float) -> Verification:
    """OpenSSL-style: build the path from the leaf through the sent certificates to a
    trusted anchor, then check every certificate's validity period."""
    if not chain:
        return Verification(20)
    anchor_prints = {a.fingerprint() for a in anchors}
    path = [chain[0]]
    pool = chain[1:]
    current = chain[0]
    for depth in range(10):
        if current.fingerprint() in anchor_prints:
            break  # a trusted certificate
        found = next(
            (
                a
                for a in anchors
                if a.key_id == current.issuer_key_id and a.subject == current.issuer
            ),
            None,
        )
        if found is not None:
            path.append(found)
            break
        if current.self_signed:
            return Verification(18 if depth == 0 else 19, depth, path)
        sent = next(
            (c for c in pool if c.key_id == current.issuer_key_id and c.subject == current.issuer),
            None,
        )
        if sent is None:
            return Verification(20, depth, path)
        if not sent.ca:
            return Verification(24, depth + 1, path)
        path.append(sent)
        current = sent
    for depth in range(len(path) - 1, -1, -1):
        cert = path[depth]
        if now < cert.not_before:
            return Verification(9, depth, path)
        if now > cert.not_after:
            return Verification(10, depth, path)
    return Verification(0, 0, path)


def rebuild_bundle(machine: Machine) -> tuple[int, int]:
    """update-ca-certificates / update-ca-trust: collect the selected and local anchors into
    the bundle file. Returns (added, removed) compared with the previous bundle."""
    from lets_linux.filesystem import FsError

    ops = machine.root_ops
    family = machine.profile.family
    before = {c.fingerprint() for c in trusted(machine)}
    pems: list[str] = []
    names: list[tuple[str, str]] = []  # (link name, source path)
    try:
        if family in ("debian", "generic"):
            selected: list[str] = []
            if ops.exists("/etc/ca-certificates.conf"):
                for line in ops.read_text("/etc/ca-certificates.conf").splitlines():
                    line = line.strip()
                    if line and not line.startswith(("#", "!")):
                        selected.append(f"/usr/share/ca-certificates/{line}")
            local = _walk(ops, "/usr/local/share/ca-certificates", ".crt")
            for path in selected + local:
                if ops.exists(path):
                    text = ops.read_text(path)
                    if certificates(text):
                        pems.append(text)
                        names.append((path.rsplit("/", 1)[-1].removesuffix(".crt") + ".pem", path))
        else:
            sources = {
                "fedora": ["/usr/share/pki/ca-trust-source/anchors", "/etc/pki/ca-trust/source/anchors"],
                "arch": ["/usr/share/ca-certificates/trust-source/anchors", "/etc/ca-certificates/trust-source/anchors"],
            }.get(family, [])  # fmt: skip
            for d in sources:
                for path in _walk(ops, d, ""):
                    text = ops.read_text(path)
                    if certificates(text):
                        pems.append(text)
        bundle = "".join(p if p.endswith("\n") else p + "\n" for p in pems)
        if family == "fedora":
            target = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
        elif family == "arch":
            target = "/etc/ca-certificates/extracted/tls-ca-bundle.pem"
        else:
            target = "/etc/ssl/certs/ca-certificates.crt"
        parent = target.rsplit("/", 1)[0]
        if not ops.exists(parent):
            ops.mkdir(parent, parents=True)
        ops.write_text(target, bundle)
        ops.chmod(target, 0o644)
        if family in ("debian", "generic"):
            for link, source in names:
                if not ops.exists(f"/etc/ssl/certs/{link}", follow=False):
                    ops.symlink(source, f"/etc/ssl/certs/{link}")
    except FsError:
        return 0, 0
    after = {c.fingerprint() for c in trusted(machine)}
    return len(after - before), len(before - after)


def _walk(ops: Any, directory: str, suffix: str) -> list[str]:
    from lets_linux.filesystem import FsError

    out: list[str] = []
    try:
        for name in sorted(ops.listdir(directory)):
            path = f"{directory}/{name}"
            if ops.stat(path).is_dir:
                out += _walk(ops, path, suffix)
            elif name.endswith(suffix):
                out.append(path)
    except FsError:
        pass
    return out


def install_store(machine: Machine) -> None:
    """ca-certificates (postinst): ship the public roots and build the bundle."""
    ops = machine.root_ops
    family = machine.profile.family
    public = [a for a in AUTHORITIES.values() if a.public]
    if family in ("debian", "generic"):
        base = "/usr/share/ca-certificates/mozilla"
        if not ops.exists(base):
            ops.mkdir(base, parents=True)
        for a in public:
            ops.write_text(f"{base}/{a.filename}", a.cert.to_pem())
        if not ops.exists("/usr/local/share/ca-certificates"):
            ops.mkdir("/usr/local/share/ca-certificates", parents=True)
        if not ops.exists("/etc/ca-certificates.conf"):
            ops.write_text("/etc/ca-certificates.conf",
                           "# This file lists certificates that you wish to use or to ignore to be\n"
                           "# installed in /etc/ssl/certs.\n# update-ca-certificates(8) will update /etc/ssl/certs by reading this file.\n#\n"
                           "# This is autogenerated by dpkg-reconfigure ca-certificates.\n"
                           "# Certificates should be installed under /usr/share/ca-certificates\n"
                           "# and files with extension '.crt' is recognized as available certs.\n#\n"
                           "# line begins with # is comment.\n# line begins with ! is certificate filename to be deselected.\n#\n"
                           + "".join(f"mozilla/{a.filename}\n" for a in public))  # fmt: skip
        if not ops.exists("/etc/ssl/certs"):
            ops.mkdir("/etc/ssl/certs", parents=True)
    else:
        base = "/usr/share/pki/ca-trust-source/anchors" if family == "fedora" else \
            "/usr/share/ca-certificates/trust-source/anchors"  # fmt: skip
        if not ops.exists(base):
            ops.mkdir(base, parents=True)
        for a in public:
            ops.write_text(f"{base}/{a.filename}", a.cert.to_pem())
        local = (
            "/etc/pki/ca-trust/source/anchors"
            if family == "fedora"
            else "/etc/ca-certificates/trust-source/anchors"
        )
        if not ops.exists(local):
            ops.mkdir(local, parents=True)
    rebuild_bundle(machine)
    if family == "fedora":
        for d in ("/etc/pki/tls/certs",):
            if not ops.exists(d):
                ops.mkdir(d, parents=True)
        if not ops.exists("/etc/pki/tls/certs/ca-bundle.crt", follow=False):
            ops.symlink(
                "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
                "/etc/pki/tls/certs/ca-bundle.crt",
            )
        if not ops.exists("/etc/ssl", follow=False):
            ops.mkdir("/etc/ssl", parents=True)
        if not ops.exists("/etc/ssl/certs", follow=False):
            ops.symlink("/etc/pki/tls/certs", "/etc/ssl/certs")
    elif family == "arch":
        if not ops.exists("/etc/ssl/certs"):
            ops.mkdir("/etc/ssl/certs", parents=True)
        if not ops.exists("/etc/ssl/certs/ca-certificates.crt", follow=False):
            ops.symlink(
                "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
                "/etc/ssl/certs/ca-certificates.crt",
            )


def openssl_date(ts: float) -> str:
    """'Mar  2 09:00:00 2026 GMT' as openssl prints validity dates."""
    d = _dt.datetime.fromtimestamp(ts, tz=_dt.UTC)
    return f"{d.strftime('%b')} {d.day:>2} {d.strftime('%H:%M:%S %Y')} GMT"
