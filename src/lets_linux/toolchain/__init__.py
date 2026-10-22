"""A simulated C toolchain: preprocessor, parser, compiler driver and the runtime of compiled programs.

The supported language is a documented subset of C (see docs/LINUX_SIMULATION_SPEC.md §11b):
enough for the programs of the development chapter — functions, int/long/char/double
variables and arrays, pointers to strings and buffers, control flow, the common parts of
stdio/stdlib/string/math — compiled with gcc-like diagnostics and linked against simulated
libraries. A compiled program stores its syntax tree in the ELF metadata
(systems/elf.py); running it interprets that tree. Nothing is ever executed on the host.
"""
