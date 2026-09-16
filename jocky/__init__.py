"""
JOCKY — a forensic scripting language and runtime (SIH26148).

The package is split into four layers:

* ``jocky.lang``  — the language: lexer, parser, bytecode compiler, VM.
* ``jocky.poly``  — polymorphic artifact encoder (unique bytes per build).
* ``jocky.rt``    — the forensic runtime: /proc, /proc/net, /sys collectors
                    and detection heuristics, exposed to scripts as natives.
* ``jocky.agent`` — central management: job server and polling agent.
"""

__version__ = "1.6.0"

__all__ = ["__version__"]
