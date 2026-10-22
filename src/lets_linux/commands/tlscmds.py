"""openssl (a subset), update-ca-certificates and update-ca-trust — over systems/tls.py.

openssl subcommands: version, genrsa, genpkey, rsa/pkey (-check, -modulus, -pubout, -text),
req (-new, -x509, -newkey, -key, -nodes/-noenc, -keyout, -subj, -addext, -days, -in with
-noout/-text/-subject/-verify), x509 (-in, -noout, -text, -subject, -issuer, -dates,
-startdate, -enddate, -serial, -fingerprint, -ext subjectAltName, -checkend, -modulus,
-pubkey; -req with -CA/-CAkey/-signkey, -extfile, -copy_extensions, -days), verify
(-CAfile, -CApath, -untrusted), s_client (-connect, -servername, -showcerts, -CAfile,
-verify_return_error, -brief), dgst/sha256/sha1/md5 and rand (-hex, -base64).
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from functools import partial
from typing import Any

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.systems import tls
from lets_linux.systems.tls import CSR, KEY, Certificate, PrivateKey, SigningRequest

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

VERSIONS = {
    "debian": "OpenSSL 3.0.15 3 Sep 2024 (Library: OpenSSL 3.0.15 3 Sep 2024)",
    "ubuntu": "OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)",
    "fedora": "OpenSSL 3.2.2 4 Jun 2024 (Library: OpenSSL 3.2.2 4 Jun 2024)",
    "arch": "OpenSSL 3.4.0 22 Oct 2024 (Library: OpenSSL 3.4.0 22 Oct 2024)",
    "generic": "OpenSSL 3.0.15 3 Sep 2024 (Library: OpenSSL 3.0.15 3 Sep 2024)",
}
ERR = "40C7B8E1F27F0000"


class OpenSSLError(Exception):
    def __init__(self, message: str, status: int = 1) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


#: options that take a value, per subcommand family (the rest are flags)
VALUED = {
    "-in", "-out", "-key", "-keyout", "-newkey", "-days", "-subj", "-addext", "-CA", "-CAkey", "-CAfile",
    "-CApath", "-untrusted", "-connect", "-servername", "-algorithm", "-pkeyopt", "-ext", "-checkend",
    "-set_serial", "-extfile", "-extensions", "-copy_extensions", "-signkey", "-config", "-nameopt",
    "-passout", "-passin", "-inform", "-outform", "-verify_hostname", "-reqexts", "-sigopt", "-CAserial",
}  # fmt: skip


@dataclass
class Options:
    flags: list[str] = field(default_factory=list)  # in the order given
    values: dict[str, list[str]] = field(default_factory=dict)
    args: list[str] = field(default_factory=list)

    def has(self, *names: str) -> bool:
        return any(n in self.flags or n in self.values for n in names)

    def get(self, name: str, default: str | None = None) -> str | None:
        vals = self.values.get(name)
        return vals[-1] if vals else default


def _parse(argv: list[str]) -> Options:
    o = Options()
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--"):
            a = a[1:]
        if a.startswith("-") and len(a) > 1:
            if a in VALUED:
                if i + 1 >= len(argv):
                    raise OpenSSLError(f"{a[1:]}: Option -{a[1:]} needs a value")
                o.values.setdefault(a, []).append(argv[i + 1])
                o.flags.append(a)
                i += 2
                continue
            o.flags.append(a)
        else:
            o.args.append(a)
        i += 1
    return o


def _read(ctx: CommandContext, path: str | None, what: str) -> str:
    if path is None or path == "-":
        return ctx.read_stdin_text()
    try:
        return ctx.fs.read_text(path)
    except FsError:
        raise OpenSSLError(f"Could not open file or uri for loading {what} from {path}\n"
                           f"{ERR}:error:80000002:system library:file_open:No such file or directory:"
                           f"../providers/implementations/storemgmt/file_store.c:267:calling stat({path})") from None  # fmt: skip


def _load_cert(ctx: CommandContext, path: str | None) -> tuple[Certificate, str]:
    text = _read(ctx, path, "certificate")
    certs = tls.certificates(text)
    if not certs:
        raise OpenSSLError(
            f"Could not read certificate from {path or '<stdin>'}\nUnable to load certificate"
        )
    return certs[0], text


def _load_key(ctx: CommandContext, path: str | None, passin: str | None = None) -> PrivateKey:
    text = _read(ctx, path, "private key")
    for kind, data in tls.pem_blocks(text):
        if kind in (KEY, "ENCRYPTED PRIVATE KEY") and data is not None:
            if data.get("enc"):
                password = passin.removeprefix("pass:") if passin else ctx.host.read_line(
                    f"Enter pass phrase for {path}:", secret=True)  # fmt: skip
                if password is None or hashlib.sha256(password.encode()).hexdigest() != data["enc"]:
                    raise OpenSSLError(f"Could not read private key from {path}\n{ERR}:error:1C800064:Provider "
                                       "routines:ossl_cipher_unpadblock:bad decrypt")  # fmt: skip
            return PrivateKey.from_data(data)
    raise OpenSSLError(f"Could not read private key from {path or '<stdin>'}")


def _write(ctx: CommandContext, path: str | None, text: str, *, private: bool = False) -> None:
    if path is None or path == "-":
        ctx.out(text)
        return
    try:
        ctx.fs.write_text(path, text)
        if private:
            ctx.fs.chmod(path, 0o600)
    except FsError as exc:
        raise OpenSSLError(
            f"Could not open file or uri for writing {path}: {exc.message}"
        ) from None


def _new_key(ctx: CommandContext, spec: str) -> PrivateKey:
    kind, _, size = spec.partition(":")
    kind = kind.lower()
    key_id = f"{ctx.machine.rng.getrandbits(160):040x}"
    if kind in ("rsa", ""):
        bits = int(size) if size.isdigit() else 2048
        if bits < 512:
            raise OpenSSLError(f"Error generating RSA key: key size {bits} too small")
        return PrivateKey(key_id, "RSA", bits)
    if kind in ("ec", "ecdsa"):
        return PrivateKey(key_id, "EC", 256)
    if kind == "ed25519":
        return PrivateKey(key_id, "ED25519", 256)
    raise OpenSSLError(f"Unknown algorithm {spec}")


def _key_pem(key: PrivateKey, password: str | None) -> str:
    if password:
        return tls.to_pem("ENCRYPTED PRIVATE KEY", {"key": key.key_id, "type": key.key_type, "bits": key.bits,
                                                    "enc": hashlib.sha256(password.encode()).hexdigest()})  # fmt: skip
    return key.to_pem()


def _hexdump(seed: str, count: int, indent: str) -> str:
    digest = (hashlib.sha512(seed.encode()).hexdigest() * 4)[: count * 2]
    pairs = [digest[i : i + 2] for i in range(0, len(digest), 2)]
    rows = [":".join(pairs[i : i + 15]) for i in range(0, len(pairs), 15)]
    return "\n".join(indent + r + (":" if k < len(rows) - 1 else "") for k, r in enumerate(rows))


def x509_text(cert: Certificate) -> str:
    serial = cert.serial.lower()
    serial_hex = ":".join(serial[i : i + 2] for i in range(0, len(serial), 2))
    lines = [
        "Certificate:", "    Data:", "        Version: 3 (0x2)", "        Serial Number:", f"            {serial_hex}",
        "        Signature Algorithm: sha256WithRSAEncryption", f"        Issuer: {cert.issuer_line()}", "        Validity",
        f"            Not Before: {tls.openssl_date(cert.not_before)}",
        f"            Not After : {tls.openssl_date(cert.not_after)}", f"        Subject: {cert.subject_line()}",
        "        Subject Public Key Info:",
    ]  # fmt: skip
    if cert.key_type == "RSA":
        lines += ["            Public Key Algorithm: rsaEncryption", f"                Public-Key: ({cert.bits} bit)",
                  "                Modulus:", _hexdump(cert.key_id, min(cert.bits // 8, 45), "                    ") + ":...",
                  "                Exponent: 65537 (0x10001)"]  # fmt: skip
    else:
        lines += [f"            Public Key Algorithm: {'id-ecPublicKey' if cert.key_type == 'EC' else 'ED25519'}",
                  f"                Public-Key: ({cert.bits} bit)"]  # fmt: skip
    lines += ["        X509v3 extensions:", "            X509v3 Basic Constraints: critical",
              f"                CA:{'TRUE' if cert.ca else 'FALSE'}"]  # fmt: skip
    if not cert.ca:
        lines += ["            X509v3 Key Usage: critical", "                Digital Signature, Key Encipherment",
                  "            X509v3 Extended Key Usage: ", "                TLS Web Server Authentication"]  # fmt: skip
    else:
        lines += [
            "            X509v3 Key Usage: critical",
            "                Certificate Sign, CRL Sign",
        ]
    if cert.sans:
        lines += ["            X509v3 Subject Alternative Name: ",
                  "                " + ", ".join(s.replace("IP:", "IP Address:") for s in cert.sans)]  # fmt: skip
    lines += ["            X509v3 Subject Key Identifier: ", "                " + _ski(cert.key_id)]
    if not cert.self_signed:
        lines += [
            "            X509v3 Authority Key Identifier: ",
            "                " + _ski(cert.issuer_key_id),
        ]
    lines += ["    Signature Algorithm: sha256WithRSAEncryption", "    Signature Value:",
              _hexdump(cert.serial + cert.issuer_key_id, 54, "        ") + ":..."]  # fmt: skip
    return "\n".join(lines) + "\n"


def _ski(key_id: str) -> str:
    h = key_id.upper()[:40]
    return ":".join(h[i : i + 2] for i in range(0, len(h), 2))


# ------------------------------------------------------------------ the command


@_cmd("openssl", "OpenSSL command line program (a subset: keys, requests, certificates, verify, s_client).",
      usage="openssl COMMAND [options]", auto_parse=False, category="network", learn=("i.tls-concepts",))  # fmt: skip
def openssl(ctx: CommandContext) -> int:
    argv = ctx.argv[1:]
    if not argv:
        ctx.stderr.write(
            "openssl: interactive mode is not supported here; give a command (openssl help)\n"
        )
        return 1
    sub, rest = argv[0], argv[1:]
    handlers = {
        "version": _version, "genrsa": _genrsa, "genpkey": _genpkey, "rsa": _pkey, "pkey": _pkey, "req": _req,
        "x509": _x509, "verify": _verify, "s_client": _s_client, "dgst": _dgst, "sha256": _dgst, "sha1": _dgst,
        "md5": _dgst, "sha512": _dgst, "rand": _rand, "help": _help,
    }  # fmt: skip
    handler = handlers.get(sub)
    if handler is None:
        ctx.stderr.write(f"Invalid command '{sub}'; type \"help\" for a list.\n")
        return 1
    try:
        return handler(ctx, sub, _parse(rest))
    except OpenSSLError as exc:
        ctx.stderr.write(exc.message.rstrip("\n") + "\n")
        return exc.status
    except ValueError as exc:
        ctx.stderr.write(f"{sub}: {exc}\n")
        return 1


def _help(ctx: CommandContext, _sub: str, _o: Options) -> int:
    ctx.outln("help:\n\nStandard commands\ndgst              genpkey           genrsa            help\npkey              rand"
              "              req               rsa\ns_client          verify            version           x509\n\n"
              "Message Digest commands (see the `dgst' command for more details)\nmd5               sha1"
              "              sha256            sha512")  # fmt: skip
    return 0


def _version(ctx: CommandContext, _sub: str, o: Options) -> int:
    profile = ctx.machine.profile
    ctx.outln(VERSIONS.get(profile.id, VERSIONS.get(profile.family, VERSIONS["generic"])))
    if "-a" in o.flags:
        ctx.outln(
            'built on: Tue Sep  3 12:00:00 2024 UTC\nplatform: debian-amd64\nOPENSSLDIR: "/usr/lib/ssl"'
        )
    return 0


def _genrsa(ctx: CommandContext, _sub: str, o: Options) -> int:
    bits = o.args[-1] if o.args else "2048"
    if not bits.isdigit():
        raise OpenSSLError(f'genrsa: Extra option: "{bits}"')
    key = _new_key(ctx, f"rsa:{bits}")
    ctx.stderr.write("." * 7 + "+++++\n" + "." * 12 + "+++++\n")
    _write(ctx, o.get("-out"), _key_pem(key, _passout(ctx, o, encrypt=o.has("-aes256", "-aes128", "-des3"))),
           private=True)  # fmt: skip
    return 0


def _passout(ctx: CommandContext, o: Options, *, encrypt: bool) -> str | None:
    if not encrypt:
        return None
    given = o.get("-passout")
    if given:
        return given.removeprefix("pass:")
    first = ctx.host.read_line("Enter PEM pass phrase:", secret=True)
    second = ctx.host.read_line("Verifying - Enter PEM pass phrase:", secret=True)
    if not first:
        raise OpenSSLError("Error: empty pass phrase or no terminal to read it from")
    if first != second:
        raise OpenSSLError("Verify failure\nbad password read")
    return first


def _genpkey(ctx: CommandContext, _sub: str, o: Options) -> int:
    algorithm = (o.get("-algorithm") or "").upper()
    if not algorithm:
        raise OpenSSLError("genpkey: no keytype specified\ngenpkey: Use -help for summary.")
    bits = "2048"
    for opt in o.values.get("-pkeyopt", []):
        if opt.startswith("rsa_keygen_bits:"):
            bits = opt.split(":", 1)[1]
    spec = {"RSA": f"rsa:{bits}", "EC": "ec", "ED25519": "ed25519"}.get(algorithm)
    if spec is None:
        raise OpenSSLError(f"genpkey: Algorithm {algorithm} not found")
    key = _new_key(ctx, spec)
    _write(ctx, o.get("-out"), _key_pem(key, _passout(ctx, o, encrypt=o.has("-aes256", "-aes-256-cbc"))),
           private=True)  # fmt: skip
    return 0


def _pkey(ctx: CommandContext, sub: str, o: Options) -> int:
    key = _load_key(ctx, o.get("-in"), o.get("-passin"))
    if "-check" in o.flags:
        ctx.outln("RSA key ok" if sub == "rsa" else "Key is valid")
    if "-modulus" in o.flags:
        ctx.outln(f"Modulus={key.modulus}")
    if "-text" in o.flags:
        ctx.outln(
            f"Private-Key: ({key.bits} bit, 2 primes)\nmodulus:\n{_hexdump(key.key_id, 30, '    ')}:..."
        )
    if "-pubout" in o.flags:
        _write(ctx, o.get("-out"), tls.to_pem("PUBLIC KEY", {"key": key.key_id, "type": key.key_type,
                                                             "bits": key.bits}))  # fmt: skip
    elif "-noout" not in o.flags and not o.has("-check", "-modulus", "-text"):
        _write(ctx, o.get("-out"), key.to_pem(), private=True)
    return 0


def _subject(ctx: CommandContext, o: Options) -> dict[str, str]:
    subj = o.get("-subj")
    if subj is not None:
        subject = tls.parse_subject(subj)
        if not subject:
            raise OpenSSLError("req: Subject does not start with '/'.")
        return subject
    if not ctx.host.has_terminal():
        raise OpenSSLError("req: no -subj given and no terminal to ask for the subject")
    ctx.outln("You are about to be asked to enter information that will be incorporated\ninto your certificate "
              "request.\nWhat you are about to enter is what is called a Distinguished Name or a DN.\n"
              "There are quite a few fields but you can leave some blank\nFor some fields there will be a "
              "default value,\nIf you enter '.', the field will be left blank.\n-----")  # fmt: skip
    out: dict[str, str] = {}
    for key, prompt, default in (("C", "Country Name (2 letter code) [AU]:", "AU"),
                                 ("ST", "State or Province Name (full name) [Some-State]:", "Some-State"),
                                 ("L", "Locality Name (eg, city) []:", ""),
                                 ("O", "Organization Name (eg, company) [Internet Widgits Pty Ltd]:", "Internet Widgits Pty Ltd"),
                                 ("OU", "Organizational Unit Name (eg, section) []:", ""),
                                 ("CN", "Common Name (e.g. server FQDN or YOUR name) []:", ""),
                                 ("emailAddress", "Email Address []:", "")):  # fmt: skip
        answer = ctx.host.read_line(prompt)
        value = (answer or "").strip() or default
        if value and value != ".":
            out[key] = value
    return out


def _req(ctx: CommandContext, _sub: str, o: Options) -> int:
    if not o.has("-new", "-x509", "-newkey") and o.get("-in") is not None:
        text = _read(ctx, o.get("-in"), "certificate request")
        data = next(
            (d for k, d in tls.pem_blocks(text) if k in (CSR, "NEW CERTIFICATE REQUEST") and d),
            None,
        )
        if data is None:
            raise OpenSSLError(
                f"Could not read certificate request from {o.get('-in')}\nUnable to load X509 request"
            )
        csr = SigningRequest.from_data(data)
        if "-verify" in o.flags:
            ctx.stderr.write("Certificate request self-signature verify OK\n")
        if "-subject" in o.flags:
            ctx.outln(f"subject={tls._fmt_name(csr.subject)}")
        if "-text" in o.flags:
            ctx.outln("Certificate Request:\n    Data:\n        Version: 1 (0x0)\n"
                      f"        Subject: {tls._fmt_name(csr.subject)}\n        Subject Public Key Info:\n"
                      f"            Public Key Algorithm: rsaEncryption\n                Public-Key: ({csr.bits} bit)\n"
                      "        Attributes:\n" + ("            Requested Extensions:\n                X509v3 Subject "
                      "Alternative Name: \n                    " + ", ".join(csr.sans) + "\n" if csr.sans else
                      "            (none)\n"))  # fmt: skip
        if "-noout" not in o.flags:
            _write(ctx, o.get("-out"), csr.to_pem())
        return 0
    if o.get("-key"):
        key = _load_key(ctx, o.get("-key"), o.get("-passin"))
    else:
        key = _new_key(ctx, o.get("-newkey") or "rsa:2048")
        encrypt = not o.has("-nodes", "-noenc")
        password = _passout(ctx, o, encrypt=encrypt) if encrypt else None
        ctx.stderr.write("." * 9 + "+++++\n" + "." * 5 + "+++++\n-----\n")
        keyout = o.get("-keyout") or "privkey.pem"
        _write(ctx, keyout, _key_pem(key, password), private=True)
    subject = _subject(ctx, o)
    sans: list[str] = []
    for ext in o.values.get("-addext", []):
        if ext.strip().startswith("subjectAltName"):
            sans += tls.parse_sans(ext)
    if "-x509" in o.flags:
        days = float(o.get("-days") or 30)
        cert = tls.issue(subject, key.key_id, None, "", not_before=ctx.machine.now(), days=days, ca=True,
                         sans=sans, bits=key.bits, key_type=key.key_type,
                         serial=f"{ctx.machine.rng.getrandbits(128):032X}")  # fmt: skip
        _write(ctx, o.get("-out"), cert.to_pem())
        return 0
    csr = SigningRequest(subject, key.key_id, sans, key.key_type, key.bits)
    _write(ctx, o.get("-out"), csr.to_pem())
    return 0


def _extfile_sans(ctx: CommandContext, path: str, section: str | None) -> list[str]:
    text = _read(ctx, path, "extensions")
    current = ""
    sans: list[str] = []
    alt: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("["):
            current = line.strip("[] ")
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if section and current and current != section and not current.startswith("alt"):
            continue
        if key == "subjectAltName":
            if value.startswith("@"):
                sans.append(value)
            else:
                sans += tls.parse_sans(value)
        elif "." in key and key.split(".")[0].upper() in ("DNS", "IP"):
            alt.setdefault(current, []).append(f"{key.split('.')[0].upper()}:{value}")
    out: list[str] = []
    for s in sans:
        out += alt.get(s[1:], []) if s.startswith("@") else [s]
    return out


def _x509(ctx: CommandContext, _sub: str, o: Options) -> int:
    if "-req" in o.flags:
        return _x509_sign(ctx, o)
    cert, _text = _load_cert(ctx, o.get("-in"))
    for flag in o.flags:
        if flag == "-subject":
            ctx.outln(f"subject={cert.subject_line()}")
        elif flag == "-issuer":
            ctx.outln(f"issuer={cert.issuer_line()}")
        elif flag in ("-dates", "-startdate"):
            ctx.outln(f"notBefore={tls.openssl_date(cert.not_before)}")
            if flag == "-dates":
                ctx.outln(f"notAfter={tls.openssl_date(cert.not_after)}")
        elif flag == "-enddate":
            ctx.outln(f"notAfter={tls.openssl_date(cert.not_after)}")
        elif flag == "-serial":
            ctx.outln(f"serial={cert.serial}")
        elif flag == "-fingerprint":
            algo = "sha256" if "-sha256" in o.flags else "sha1"
            ctx.outln(
                f"{'sha256' if algo == 'sha256' else 'SHA1'} Fingerprint={cert.fingerprint(algo)}"
            )
        elif flag == "-modulus":
            ctx.outln(f"Modulus={PrivateKey(cert.key_id, cert.key_type, cert.bits).modulus}")
        elif flag == "-pubkey":
            ctx.out(
                tls.to_pem(
                    "PUBLIC KEY", {"key": cert.key_id, "type": cert.key_type, "bits": cert.bits}
                )
            )
        elif flag == "-ext":
            for name in (o.get("-ext") or "").split(","):
                if name.strip() == "subjectAltName" and cert.sans:
                    ctx.outln("X509v3 Subject Alternative Name: \n    "
                              + ", ".join(s.replace("IP:", "IP Address:") for s in cert.sans))  # fmt: skip
                elif name.strip() == "basicConstraints":
                    ctx.outln(
                        f"X509v3 Basic Constraints: critical\n    CA:{'TRUE' if cert.ca else 'FALSE'}"
                    )
        elif flag == "-text":
            ctx.out(x509_text(cert))
    if "-checkend" in o.values:
        seconds = float(o.get("-checkend") or 0)
        if cert.not_after < ctx.machine.now() + seconds:
            ctx.outln("Certificate will expire")
            return 1
        ctx.outln("Certificate will not expire")
        return 0
    if "-noout" not in o.flags:
        _write(ctx, o.get("-out"), cert.to_pem())
    return 0


def _x509_sign(ctx: CommandContext, o: Options) -> int:
    text = _read(ctx, o.get("-in"), "certificate request")
    data = next(
        (d for k, d in tls.pem_blocks(text) if k in (CSR, "NEW CERTIFICATE REQUEST") and d), None
    )
    if data is None:
        raise OpenSSLError(f"Could not read certificate request from {o.get('-in') or '<stdin>'}")
    csr = SigningRequest.from_data(data)
    days = float(o.get("-days") or 30)
    sans: list[str] = []
    if o.get("-extfile"):
        sans = _extfile_sans(ctx, str(o.get("-extfile")), o.get("-extensions"))
    if o.get("-copy_extensions") in ("copy", "copyall") and not sans:
        sans = list(csr.sans)
    serial = o.get("-set_serial")
    serial_hex = (
        f"{ctx.machine.rng.getrandbits(128):032X}" if serial is None else f"{int(serial, 0):02X}"
    )
    if o.get("-signkey"):
        key = _load_key(ctx, o.get("-signkey"), o.get("-passin"))
        if key.key_id != csr.key_id:
            raise OpenSSLError("x509: Error: Certificate request and private key do not match")
        cert = tls.issue(csr.subject, csr.key_id, None, "", not_before=ctx.machine.now(), days=days, sans=sans,
                         serial=serial_hex, bits=csr.bits, key_type=csr.key_type)  # fmt: skip
    else:
        if not o.get("-CA"):
            raise OpenSSLError(
                "x509: We need a private key to sign with, use -key or -CAkey or -CA with private key"
            )
        ca, _t = _load_cert(ctx, o.get("-CA"))
        ca_key = _load_key(ctx, o.get("-CAkey") or o.get("-CA"), o.get("-passin"))
        if ca_key.key_id != ca.key_id:
            raise OpenSSLError("x509: CA certificate and CA private key do not match")
        cert = tls.issue(csr.subject, csr.key_id, ca, ca.key_id, not_before=ctx.machine.now(), days=days,
                         sans=sans, serial=serial_hex, bits=csr.bits, key_type=csr.key_type)  # fmt: skip
        if "-CAcreateserial" in o.flags:
            srl = str(o.get("-CA")).rsplit(".", 1)[0] + ".srl"
            _write(ctx, srl, cert.serial + "\n")
    ctx.stderr.write(
        f"Certificate request self-signature ok\nsubject={tls._fmt_name(csr.subject)}\n"
    )
    _write(ctx, o.get("-out"), cert.to_pem())
    return 0


def _verify(ctx: CommandContext, _sub: str, o: Options) -> int:
    anchors = tls.trusted(ctx.machine)
    if o.get("-CAfile"):
        anchors += tls.certificates(_read(ctx, o.get("-CAfile"), "CA certificates"))
    if o.get("-CApath"):
        anchors += tls.trusted(ctx.machine, capath=o.get("-CApath"))
    untrusted = (
        tls.certificates(_read(ctx, o.get("-untrusted"), "certificates"))
        if o.get("-untrusted")
        else []
    )
    status = 0
    for path in o.args or ["-"]:
        cert, _text = _load_cert(ctx, path)
        result = tls.verify([cert, *untrusted], anchors, ctx.machine.now())
        name = "stdin" if path == "-" else path
        if result.ok:
            ctx.outln(f"{name}: OK")
            continue
        failing = result.path[result.depth] if result.depth < len(result.path) else cert
        ctx.stderr.write(f"{failing.subject_line()}\nerror {result.code} at {result.depth} depth lookup: "
                         f"{result.message}\nerror {name}: verification failed\n")  # fmt: skip
        status = 2
    return status


@dataclass
class Handshake:
    chain: list[Certificate] = field(default_factory=list)
    error: str = ""  # a connection or TLS failure (no certificate)
    errno: int = 0


def handshake(machine: Any, ip: str, port: int, servername: str) -> Handshake:
    """Connect to IP:PORT and read the certificate chain a TLS server sends (if it speaks TLS)."""
    from lets_linux.systems.world import Outcome

    conn = machine.world.connect(machine, ip, port)
    if conn.outcome is not Outcome.OK:
        errno = {Outcome.REFUSED: 111, Outcome.TIMEOUT: 110, Outcome.HOST_UNREACHABLE: 113,
                 Outcome.NET_UNREACHABLE: 101}.get(conn.outcome, 111)  # fmt: skip
        return Handshake(error="connect", errno=errno)
    return chain_from(machine, conn, servername, port)


def chain_from(machine: Any, conn: Any, servername: str, port: int) -> Handshake:
    """The certificate chain on an established connection (error: the server does not speak TLS)."""
    if conn.socket is not None:
        from lets_linux.commands import nginx

        host = conn.machine or machine
        proc = host.procs.get(conn.socket.pid)
        if proc is None or not proc.program.startswith("nginx"):
            return Handshake(error="wrong version number")
        server = nginx.ssl_server(host, conn.socket.port, servername, proc.root)
        if server is None:
            return Handshake(error="wrong version number")
        return Handshake(chain=tls.certificates(server.get("cert_pem", "")))
    service = conn.service
    if service is None or service.kind != "https" or conn.path.peer is None:
        return Handshake(error="wrong version number")
    return Handshake(chain=machine.world.certificate_chain(conn.path.peer, port))


def _s_client(ctx: CommandContext, _sub: str, o: Options) -> int:
    from lets_linux.systems.resolver import getaddrinfo

    target = o.get("-connect") or (o.args[0] if o.args else "")
    host, _, port_text = target.rpartition(":") if ":" in target else (target, "", "443")
    if not host or not port_text.isdigit():
        raise OpenSSLError("s_client: -connect argument or target parameter malformed or ambiguous")
    port = int(port_text)
    res = getaddrinfo(ctx.machine, host)
    if not res.addresses:
        raise OpenSSLError(f"BIO_lookup_ex: system lib\n{ERR}:error:10080002:BIO routines:BIO_lookup_ex:system lib:"
                           f"../crypto/bio/bio_addr.c:738:Name or service not known\nconnect:errno=0")  # fmt: skip
    servername = o.get("-servername") or host
    hs = handshake(ctx.machine, res.addresses[0], port, servername)
    if hs.error == "connect":
        text = {111: "Connection refused", 110: "Connection timed out", 113: "No route to host",
                101: "Network is unreachable"}[hs.errno]  # fmt: skip
        if hs.errno == 110:
            ctx.machine.clock.advance(130)
        raise OpenSSLError(f"{ERR}:error:8000006F:system library:BIO_connect:{text}:../crypto/bio/bio_sock2.c:114:"
                           f"calling connect()\n{ERR}:error:10000067:BIO routines:BIO_connect:connect error:"
                           f"../crypto/bio/bio_sock2.c:116:\nconnect:errno={hs.errno}")  # fmt: skip
    ctx.outln("CONNECTED(00000003)")
    if hs.error:
        ctx.stderr.write(f"{ERR}:error:0A00010B:SSL routines:ssl3_get_record:wrong version number:"
                         "../ssl/record/ssl3_record.c:354:\n")  # fmt: skip
        ctx.outln("---\nno peer certificate available\n---\nNo client certificate CA names sent\n---\n"
                  "SSL handshake has read 5 bytes and written 312 bytes\nVerification: OK\n---\n"
                  "New, (NONE), Cipher is (NONE)\n---")  # fmt: skip
        return 1
    anchors = (
        tls.trusted(ctx.machine, cafile=o.get("-CAfile"))
        if o.get("-CAfile")
        else tls.trusted(ctx.machine)
    )
    result = tls.verify(hs.chain, anchors, ctx.machine.now())
    brief = "-brief" in o.flags
    path = result.path
    if not brief:
        for depth in range(len(path) - 1, -1, -1):
            cert = path[depth]
            ctx.stderr.write(f"depth={depth} {cert.subject_line()}\n")
            if not result.ok and depth == result.depth:
                ctx.stderr.write(f"verify error:num={result.code}:{result.message}\n")
                if result.code == 10:
                    ctx.stderr.write(f"notAfter={tls.openssl_date(cert.not_after)}\n")
                if result.code == 20 and depth == 0 and len(hs.chain) == 1:
                    ctx.stderr.write(
                        "verify return:1\nverify error:num=21:unable to verify the first certificate\n"
                    )
            ctx.stderr.write("verify return:1\n")
    if result.code == 20 and result.depth == 0 and len(hs.chain) == 1:
        result = tls.Verification(21, 0, result.path)  # s_client ends with the leaf-signature error
    if not result.ok and "-verify_return_error" in o.flags:
        ctx.stderr.write(f"{ERR}:error:0A000086:SSL routines:tls_post_process_server_certificate:certificate verify "
                         "failed:../ssl/statem/statem_clnt.c:1889:\n")  # fmt: skip
        return 1
    if brief:
        ctx.stderr.write("CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nCiphersuite: TLS_AES_256_GCM_SHA384\n"
                         f"Peer certificate: {hs.chain[0].subject_line()}\nHash used: SHA256\n"
                         f"Verification: {'OK' if result.ok else result.message}\nServer Temp Key: X25519, 253 bits\n")  # fmt: skip
        return 0
    ctx.outln("---\nCertificate chain")
    for i, cert in enumerate(hs.chain):
        ctx.outln(f" {i} s:{cert.subject_line()}\n   i:{cert.issuer_line()}\n   a:PKEY: rsaEncryption, {cert.bits} "
                  f"(bit); sigalg: RSA-SHA256\n   v:NotBefore: {tls.openssl_date(cert.not_before)}; NotAfter: "
                  f"{tls.openssl_date(cert.not_after)}")  # fmt: skip
        if "-showcerts" in o.flags:
            ctx.out(cert.to_pem())
    leaf = hs.chain[0]
    ctx.outln("---\nServer certificate")
    ctx.out(leaf.to_pem())
    ctx.outln(f"subject={leaf.subject_line()}\nissuer={leaf.issuer_line()}\n---\nNo client certificate CA names sent\n"
              "Peer signing digest: SHA256\nPeer signature type: RSA-PSS\nServer Temp Key: X25519, 253 bits\n---\n"
              f"SSL handshake has read {1400 * len(hs.chain) + 1032} bytes and written 393 bytes\n"
              f"Verification{': OK' if result.ok else ' error: ' + result.message}\n---\n"
              f"New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nServer public key is {leaf.bits} bit\n"
              "This TLS version forbids renegotiation.\nCompression: NONE\nExpansion: NONE\nNo ALPN negotiated\n"
              "Early data was not sent\n"
              f"Verify return code: {result.code} ({result.message})\n---\nDONE")  # fmt: skip
    return 0


def _dgst(ctx: CommandContext, sub: str, o: Options) -> int:
    algo = sub if sub != "dgst" else next((f[1:] for f in o.flags if f[1:] in ("sha256", "sha1", "md5", "sha512")),
                                          "sha256")  # fmt: skip
    label = {"sha256": "SHA2-256", "sha512": "SHA2-512", "sha1": "SHA1", "md5": "MD5"}[algo]
    sources = o.args or ["-"]
    for path in sources:
        if path == "-":
            data = ctx.stdin.read()
            name = "stdin"
        else:
            try:
                data = ctx.fs.read_bytes(path)
            except FsError as exc:
                raise OpenSSLError(
                    f"Could not open file or uri for loading from {path}: {exc.message}"
                ) from None
            name = path
        digest = hashlib.new(algo, data).hexdigest()
        ctx.outln(f"{label}({name})= {digest}" if "-r" not in o.flags else f"{digest} *{name}")
    return 0


def _rand(ctx: CommandContext, _sub: str, o: Options) -> int:
    if not o.args or not o.args[-1].isdigit():
        raise OpenSSLError("rand: Missing number of bytes")
    count = int(o.args[-1])
    data = bytes(ctx.machine.rng.getrandbits(8) for _ in range(count))
    if "-hex" in o.flags:
        ctx.outln(data.hex())
    elif "-base64" in o.flags:
        ctx.outln(base64.b64encode(data).decode())
    else:
        ctx.out(data.decode("latin-1"))
    return 0


# ------------------------------------------------------------------ trust store tools


@_cmd("update-ca-certificates", "Update /etc/ssl/certs and ca-certificates.crt (Debian).",
      usage="update-ca-certificates [--fresh]", auto_parse=False, category="network", learn=("i.tls-concepts",))  # fmt: skip
def update_ca_certificates(ctx: CommandContext) -> int:
    if not ctx.creds.is_root:
        ctx.stderr.write(
            "ln: failed to create symbolic link '/etc/ssl/certs/ca-certificates.pem': Permission denied\n"
        )
        return 1
    ctx.outln("Updating certificates in /etc/ssl/certs...")
    # (files without the .crt extension in /usr/local/share/ca-certificates are silently ignored)
    added, removed = tls.rebuild_bundle(ctx.machine)
    ctx.outln(
        "rehash: warning: skipping ca-certificates.crt,it does not contain exactly one certificate or CRL"
    )
    ctx.outln(
        f"{added} added, {removed} removed; done.\nRunning hooks in /etc/ca-certificates/update.d...\ndone."
    )
    return 0


@_cmd("update-ca-trust", "Manage consolidated and dynamic configuration of CA certificates (Fedora, Arch).",
      usage="update-ca-trust [extract]", auto_parse=False, category="network", learn=("i.tls-concepts",))  # fmt: skip
def update_ca_trust(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if args and args[0] not in ("extract", "--help"):
        ctx.stderr.write(
            f"Error: unknown command: '{args[0]}', see 'update-ca-trust --help' for usage.\n"
        )
        return 1
    if not ctx.creds.is_root:
        ctx.stderr.write(
            "p11-kit: couldn't create file: /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem: Permission denied\n"
        )
        return 1
    tls.rebuild_bundle(ctx.machine)
    return 0
