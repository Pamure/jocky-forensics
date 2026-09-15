"""Opt-in integrations that *consume* JOCKY instead of running it.

The runtime is stdlib-only by design, so nothing here is imported by
``jocky run``/``jocky test`` or by the collectors.  Each module declares its own
optional extra in ``pyproject.toml`` and is imported only by whoever wants it —
editor support (``jocky.contrib.pygments_lexer``), not collection.
"""
