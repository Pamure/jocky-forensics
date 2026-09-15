"""
Seeded, grammar-aware fuzzer for the JOCKY front end and the VM.

Why this exists
---------------
Code the VM executes sits behind a funnel that turns host exceptions into
script-visible ones: ``VM._run_one`` ends in ``except Exception`` and unwinds a
``JockyRuntimeError`` instead (``jocky/lang/vm.py:293``), so a crashing native
is *catchable* from a script.  ``compile_source`` has no such funnel — a bug in
the lexer, parser or compiler escapes as a raw Python exception and takes the
calling process with it.  That is exactly how ``KeyError: ''`` once escaped the
lexer for a script whose last token was a bare ``0`` at end of input; the
reproducers for it (and for two interpolation/comparison bugs of the same era)
are the first programs of every corpus produced here.

Design notes
------------
* **Grammar-aware, not byte soup.** Statements and expressions are drawn from
  the shapes the parser implements (see the grammar comment at the top of
  ``jocky/lang/parser.py``): ``let``/``set``, ``if``/``elif``/``else``,
  ``while``, ``for … in``, ``fn`` declarations and lambdas, ``try``/``catch``,
  ``emit``, blocks, member and index assignment, interpolated strings, list and
  map literals.  Identifier use is scope-tracked, so generated references point
  at something that was actually bound instead of tripping "undefined name" on
  every line: the corpus has to reach the VM's real machinery — closures,
  captures, protected regions, iterators — to be worth running.
* **A minority is malformed.** ``_DEFECTS`` applies one guaranteed-malformed
  recipe to roughly 8% of programs.  Malformed input is the front end's
  hardest case and must be *rejected* (``JockySyntaxError``), never crash;
  ``defect_sources()`` exposes one sample per recipe so the test suite can pin
  that.
* **No trailing newline.** Programs are joined with ``\n`` and never end with
  one, reproducing the end-of-input shape of the historical lexer bug.
* **Bounded budgets.** A run gets ``MAX_STEPS`` instructions and ``wall_ms``;
  the step budget normally trips first (an unbounded ``while`` costs a
  millisecond, not a wall-clock second), which keeps a large corpus cheap.
* **Bounded nesting.** Expression depth and statement nesting are capped, so
  the generated programs stay inside the *parser's* recursion headroom.  The
  front end reports its own limit rather than crashing: nesting deeper than the
  interpreter's stack (`"(" * 200 + "1" + ")" * 200`, a 600-link method chain)
  raises ``JockySyntaxError``/``JockyCompileError``.  Those shapes are pinned as
  defect recipes below, and ``HISTORICAL_REPRODUCERS`` would carry them if they
  ever stopped being rejected cleanly.
* **No clock dependence.** ``now()`` and ``sleep()`` are deliberately not
  generated: a fuzz run must not be able to fail because the host was busy.
"""
from __future__ import annotations

import pathlib
import random
import re
import sys
import traceback
from typing import Any, Callable, Dict, List, Sequence, Tuple

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky.errors import JockyError  # noqa: E402
from jocky.runner import compile_source, run_source  # noqa: E402

# ------------------------------------------------------------------- budgets
WALL_MS = 50.0
MAX_STEPS = 20_000

# Programs whose failure once escaped as a host exception.  Every corpus starts
# with these: the first ends in a bare `0` with no trailing newline (the lexer
# looked the empty string up in its escape table and raised `KeyError: ''`),
# the second interpolates that same `0`, the third chains comparisons and used
# to crash the compiler while patching jumps.
HISTORICAL_REPRODUCERS: Tuple[str, ...] = (
    "let total = 1\nemit total + 0",
    'emit "{0}"',
    "emit 3 < 2 < 1",
)

# ---------------------------------------------------------------- vocabulary
_MAX_EXPR_DEPTH = 4
_MAX_STMT_DEPTH = 3
_MAX_STMTS = 5
_DEFECT_RATE = 0.08

_NAME_POOL = ("x", "n", "acc", "items", "total", "label", "value", "flag",
              "counts", "row", "seen", "pid")

_STR_LITERALS = ('"ok"', '""', '"pid=42"', '"a\\tb"', '"\\x41"', '"\\d+"',
                 '"{{brace}}"', '"mixed Case 9"', 'r"raw\\d+"', 'R"pid=[0-9]+"',
                 'r"\\d{2,3}"')
_NUM_LITERALS = ("0", "1", "2", "3", "7", "13", "0x1f", "0b101", "0o17",
                 "1_000", "3.5", ".5", "1e3")
_OTHER_LITERALS = ("true", "false", "nil")
_JSON_LITERALS = ('"{{}}"', '"[1,2]"', '"null"', '"\\"text\\""')
_SMALL_INTS = ("0", "1", "2", "3")

# name -> argument kinds.  "fn0"/"fn1"/"fn1b"/"fn1n" build inline lambdas,
# "intlit" a small literal and "json" a JSON string literal.  Deliberately
# limited to the pure helpers: a fuzz corpus must not read the host's process
# table, and its cost must not depend on the machine.
_NATIVE_CALLS: Dict[str, Tuple[str, ...]] = {
    "print": ("any",),
    "len": ("any",),
    "str": ("any",),
    "int": ("any",),
    "float": ("any",),
    "type": ("any",),
    "range": ("intlit",),
    "transform": ("list", "fn1"),
    "filter": ("list", "fn1b"),
    "sort": ("list",),
    "sort_by": ("list", "fn1n"),
    "count": ("list",),
    "join": ("list", "str"),
    "keys": ("map",),
    "values": ("map",),
    "contains": ("any", "any"),
    "dict": (),
    "json_encode": ("any",),
    "json_decode": ("json",),
    "hex": ("num",),
    "error": ("str",),
    "assert": ("bool",),
    "expect": ("any", "any"),
    "expect_throws": ("fn0",),
    "fail": ("str",),
    "skip": ("str",),
}

# kind -> builder method names.  ``value`` picks one at random until the depth
# budget runs out, then falls back to a literal of that kind.
_VALUE_BUILDERS: Dict[str, Tuple[str, ...]] = {
    "str": ("_v_str_literal", "_v_str_interp", "_v_str_call", "_v_str_concat",
            "_v_str_method", "_v_str_join"),
    "num": ("_v_num_literal", "_v_num_arith", "_v_num_call", "_v_num_method",
            "_v_num_neg"),
    "list": ("_v_list_literal", "_v_list_range", "_v_list_keys",
             "_v_list_transform", "_v_list_method", "_v_list_split"),
    "map": ("_v_map_literal", "_v_map_dict", "_v_map_json"),
    "bool": ("_v_bool_literal", "_v_bool_compare", "_v_bool_logic",
             "_v_bool_contains", "_v_bool_member"),
    "any": ("_v_any_literal", "_v_any_name", "_v_any_value", "_v_any_method",
            "_v_any_call_native", "_v_any_call_user"),
}

# Leaf statements, used once a program is nested as deep as it may go.
_LEAF_STMTS = ("_st_let", "_st_emit", "_st_expr", "_st_assign")
_ALL_STMTS = _LEAF_STMTS + ("_st_if", "_st_for", "_st_try", "_st_fn",
                            "_st_while", "_st_block")

_STR_PRODUCING_METHODS = (("upper", ()), ("lower", ()), ("strip", ()),
                          ("replace", ("str", "str")), ("substr", ("num",)))
_NUM_PRODUCING_METHODS = (("abs", ()), ("to_int", ()), ("to_float", ()))
_COLLECTION_METHODS = (("slice", ("num",), "list"), ("reverse", (), "list"),
                           ("sort", (), "list"), ("unique", (), "list"),
                           ("chars", (), "str"), ("bytes", (), "str"),
                           ("split", ("str",), "str"), ("lines", (), "str"))


class _Gen:
    """One generated program: a random walk over the parser's own grammar.

    Scope state lives here rather than in the generated text, so ``set`` only
    targets names that exist and a lambda only references captures that were
    declared around it.
    """

    def __init__(self, rng: random.Random, defect_rate: float = _DEFECT_RATE):
        self.rng = rng
        self.defect_rate = defect_rate
        self.scopes: List[List[str]] = [[]]                    # names
        self.fn_scopes: List[List[Tuple[str, int]]] = [[]]     # (name, arity)
        self.loop_depth = 0
        self.stmt_depth = 0
        self.indent = 0

    # ---------------------------------------------------------------- scopes
    def _names(self) -> List[str]:
        return [name for scope in self.scopes for name in scope]

    def _fns(self) -> List[Tuple[str, int]]:
        return [fn for scope in self.fn_scopes for fn in scope]

    def _bind(self, name: str) -> None:
        self.scopes[-1].append(name)

    def _push_scope(self) -> None:
        self.scopes.append([])
        self.fn_scopes.append([])

    def _pop_scope(self) -> None:
        self.scopes.pop()
        self.fn_scopes.pop()

    # ------------------------------------------------------------ statements
    def program(self) -> str:
        """A whole program: no trailing newline, maybe one malformed edit."""
        stmts = [self.stmt(indent=0)
                 for _ in range(self.rng.randint(1, _MAX_STMTS))]
        source = "\n".join(stmts)
        if self.rng.random() < self.defect_rate:
            _, apply = self.rng.choice(_DEFECTS)
            source = apply(self.rng, source)
        return source

    def stmt(self, indent: int) -> str:
        names = _LEAF_STMTS if self.stmt_depth >= _MAX_STMT_DEPTH else _ALL_STMTS
        if self.loop_depth:
            names += ("_st_loop_ctl",)
        return "  " * indent + getattr(self, self.rng.choice(names))()

    def block(self) -> str:
        """``{ … }`` — its own scope, one nesting level deeper."""
        self._push_scope()
        self.stmt_depth += 1
        self.indent += 1
        inner = [self.stmt(self.indent)
                 for _ in range(self.rng.randint(1, 3))]
        self.indent -= 1
        self.stmt_depth -= 1
        self._pop_scope()
        return "{\n" + "\n".join(inner) + "\n" + "  " * self.indent + "}"

    def _st_let(self) -> str:
        name = self.rng.choice(_NAME_POOL)
        kind = self.rng.choice(("any", "str", "num", "list", "map"))
        source = f"let {name} = {self.value(kind, 0)}"
        self._bind(name)
        return source

    def _st_assign(self) -> str:
        names = self._names()
        if not names:
            return self._st_let()
        target = self.rng.choice(names)
        if self.rng.random() < 0.25:
            return f'set {target}["k"] = {self.value("any", 0)}'
        return f"set {target} = {self.value('any', 0)}"

    def _st_emit(self) -> str:
        return f"emit {self.value('any', 0)}"

    def _st_expr(self) -> str:
        """An expression statement that cannot merge into the previous one.

        Newlines are insignificant, so an expression starting with ``[`` or
        ``(`` is read as an index or a call on whatever came before it, and one
        starting with ``{`` is a block.  Redraw until the statement starts with
        a token that ends the previous statement instead.
        """
        source = self.value("any", 0)
        for _ in range(3):
            if source[0] not in "{([":
                return source
            source = self.value("any", 0)
        return self.value("str", 0)          # identifier- or quote-led

    def _st_block(self) -> str:
        return self.block()

    def _st_if(self) -> str:
        parts = [f"if {self.value('bool', 0)} {self.block()}"]
        for _ in range(self.rng.randint(0, 1)):
            parts.append(f"elif {self.value('bool', 0)} {self.block()}")
        if self.rng.random() < 0.4:
            parts.append(f"else {self.block()}")
        return " ".join(parts)

    def _st_while(self) -> str:
        condition = self.value("bool", 0)
        self.loop_depth += 1
        body = self.block()
        self.loop_depth -= 1
        return f"while {condition} {body}"

    def _st_for(self) -> str:
        name = self.rng.choice(("i", "item", "entry", "seen"))
        iterable = self.value("list", 0)
        self.loop_depth += 1
        self._push_scope()
        self._bind(name)
        body = self.block()
        self._pop_scope()
        self.loop_depth -= 1
        return f"for {name} in {iterable} {body}"

    def _st_loop_ctl(self) -> str:
        """``break``/``continue`` — offered only inside a loop body."""
        return self.rng.choice(("break", "continue"))

    def _st_try(self) -> str:
        body = self.block()
        self._push_scope()
        self._bind("err")
        handler = self.block()
        self._pop_scope()
        return f"try {body} catch err {handler}"

    def _st_fn(self) -> str:
        name = self.rng.choice(("helper", "pick", "scale", "bump"))
        arity = self.rng.randint(0, 2)
        params: List[str] = []
        while len(params) < arity:
            candidate = self.rng.choice(("a", "b", "v"))
            if candidate not in params:
                params.append(candidate)
        self.fn_scopes[-1].append((name, arity))
        self._push_scope()
        for param in params:
            self._bind(param)
        loop_depth = self.loop_depth              # a function body cannot
        self.loop_depth = 0                       # break out of our loop
        result = self.value("any", 0)             # generated with params in scope
        self.loop_depth = loop_depth
        self._pop_scope()
        return (f"fn {name}({', '.join(params)}) "
                f"{{ return {result} }}")

    # ----------------------------------------------------------- expressions
    def value(self, kind: str, depth: int) -> str:
        """Source for an expression that should evaluate to ``kind``."""
        if depth >= _MAX_EXPR_DEPTH:
            return {"str": self._v_str_literal, "num": self._v_num_literal,
                    "list": self._v_list_literal, "map": self._v_map_literal,
                    "bool": self._v_bool_literal,
                    "any": self._v_any_literal}[kind](depth)
        return getattr(self, self.rng.choice(_VALUE_BUILDERS[kind]))(depth)

    # ------------------------------------------------------------ any value
    def _v_any_literal(self, depth: int) -> str:
        return self.rng.choice(_OTHER_LITERALS)

    def _v_any_name(self, depth: int) -> str:
        names = self._names()
        if not names:
            return self._v_any_literal(depth)
        return self.rng.choice(names)

    def _v_any_value(self, depth: int) -> str:
        return self.value(self.rng.choice(("str", "num", "list", "map", "bool")),
                          depth)

    def _v_any_method(self, depth: int) -> str:
        name, kinds = self.rng.choice((("get", ("str",)), ("has", ("str",)),
                                       ("len", ()), ("first", ()), ("last", ()),
                                       ("to_str", ())))
        args = ", ".join(self.arg(k, depth) for k in kinds)
        return f"{self.value('any', depth + 1)}.{name}({args})"

    def _v_any_call_native(self, depth: int) -> str:
        name = self.rng.choice(tuple(_NATIVE_CALLS))
        args = ", ".join(self.arg(kind, depth) for kind in _NATIVE_CALLS[name])
        return f"{name}({args})"

    def _v_any_call_user(self, depth: int) -> str:
        fns = self._fns()
        if not fns:
            return self._v_any_value(depth + 1)
        name, arity = self.rng.choice(fns)
        args = ", ".join(self.value("any", depth + 1) for _ in range(arity))
        return f"{name}({args})"

    def arg(self, kind: str, depth: int) -> str:
        """One call argument: a value, a small literal or an inline lambda."""
        if kind == "intlit":
            return self.rng.choice(_SMALL_INTS)
        if kind == "json":
            return self.rng.choice(_JSON_LITERALS)
        if kind.startswith("fn"):
            return self._lambda(kind, depth)
        return self.value(kind, depth + 1)

    def _lambda(self, kind: str, depth: int) -> str:
        params = [] if kind == "fn0" else ["v"]
        result = {"fn1b": "bool", "fn1n": "num"}.get(kind, "any")
        self._push_scope()
        for param in params:
            self._bind(param)
        if self.rng.random() < 0.25:
            body = (f"if {self.value('bool', depth + 1)} "
                    f"{{ return {self.value(result, depth + 1)} }}")
        else:
            body = f"return {self.value(result, depth + 1)}"
        self._pop_scope()
        return f"fn({', '.join(params)}) {{ {body} }}"

    # -------------------------------------------------------------- strings
    def _v_str_literal(self, depth: int) -> str:
        return self.rng.choice(_STR_LITERALS)

    def _v_str_interp(self, depth: int) -> str:
        # An expression whose source starts with `{` is a map literal, and
        # `"v={…"` would then read `{{` — the lexer's escape for a literal
        # brace — so the interpolation would never be entered.
        inner = self.value("any", depth + 1)
        for _ in range(2):
            if not inner.startswith("{"):
                break
            inner = self.value("any", depth + 1)
        return self.rng.choice((f'"v={{{inner}}}"', f'"{{{inner}}}"',
                                f'"{{ {inner} }}-tail"',
                                f'"n={{ {inner} }}{{ ok }}"'))

    def _v_str_call(self, depth: int) -> str:
        name, kinds = self.rng.choice((("str", ("any",)), ("type", ("any",)),
                                       ("json_encode", ("any",)),
                                       ("join", ("list", "str"))))
        args = ", ".join(self.arg(k, depth) for k in kinds)
        return f"{name}({args})"

    def _v_str_concat(self, depth: int) -> str:
        return f"{self.value('str', depth + 1)} + {self.value('str', depth + 1)}"

    def _v_str_method(self, depth: int) -> str:
        name, kinds = self.rng.choice(_STR_PRODUCING_METHODS)
        args = ", ".join(self.arg(k, depth) for k in kinds)
        return f"{self.value('str', depth + 1)}.{name}({args})"

    def _v_str_join(self, depth: int) -> str:
        return (f"join({self.value('list', depth + 1)}, "
                f"{self._v_str_literal(depth)})")

    # --------------------------------------------------------------- numbers
    def _v_num_literal(self, depth: int) -> str:
        return self.rng.choice(_NUM_LITERALS)

    def _v_num_arith(self, depth: int) -> str:
        op = self.rng.choice(("+", "-", "*", "%", "/"))
        return f"{self.value('num', depth + 1)} {op} {self.value('num', depth + 1)}"

    def _v_num_call(self, depth: int) -> str:
        name, kinds = self.rng.choice((("len", ("any",)), ("count", ("list",)),
                                       ("int", ("any",)), ("float", ("any",))))
        args = ", ".join(self.arg(k, depth) for k in kinds)
        return f"{name}({args})"

    def _v_num_method(self, depth: int) -> str:
        name, kinds = self.rng.choice(_NUM_PRODUCING_METHODS)
        args = ", ".join(self.arg(k, depth) for k in kinds)
        return f"{self.value('num', depth + 1)}.{name}({args})"

    def _v_num_neg(self, depth: int) -> str:
        return f"-{self.value('num', depth + 1)}"

    # ----------------------------------------------------------------- lists
    def _v_list_literal(self, depth: int) -> str:
        items = [self.value("any", depth + 1)
                 for _ in range(self.rng.randint(0, 3))]
        return "[" + ", ".join(items) + "]"

    def _v_list_range(self, depth: int) -> str:
        if self.rng.random() < 0.5:
            return f"range({self.rng.choice(_SMALL_INTS)})"
        return (f"range({self.rng.choice(_SMALL_INTS)}, "
                f"{self.rng.choice(_SMALL_INTS)})")

    def _v_list_keys(self, depth: int) -> str:
        function = self.rng.choice(("keys", "values"))
        return f"{function}({self.value('map', depth + 1)})"

    def _v_list_transform(self, depth: int) -> str:
        name = self.rng.choice(("transform", "filter", "sort_by"))
        fn_kind = {"transform": "fn1", "filter": "fn1b", "sort_by": "fn1n"}[name]
        return (f"{name}({self.value('list', depth + 1)}, "
                f"{self._lambda(fn_kind, depth + 1)})")

    def _v_list_method(self, depth: int) -> str:
        name, kinds, owner = self.rng.choice(_COLLECTION_METHODS)
        args = ", ".join(self.arg(k, depth) for k in kinds)
        return f"{self.value(owner, depth + 1)}.{name}({args})"

    def _v_list_split(self, depth: int) -> str:
        return f'{self.value("str", depth + 1)}.split(",")'

    # ------------------------------------------------------------------ maps
    def _v_map_literal(self, depth: int) -> str:
        pairs = []
        for _ in range(self.rng.randint(0, 3)):
            key = self.rng.choice(('"k"', '"pid"', "name", "value", "seen"))
            pairs.append(f"{key}: {self.value('any', depth + 1)}")
        return "{" + ", ".join(pairs) + "}"

    def _v_map_dict(self, depth: int) -> str:
        if self.rng.random() < 0.5:
            return "dict()"
        return (f"{self.value('map', depth + 1)}.merge("
                f"{self.value('map', depth + 1)})")

    def _v_map_json(self, depth: int) -> str:
        return f"json_decode({self.rng.choice(_JSON_LITERALS)})"

    # ----------------------------------------------------------------- bools
    def _v_bool_literal(self, depth: int) -> str:
        return self.rng.choice(("true", "false"))

    def _v_bool_compare(self, depth: int) -> str:
        op = self.rng.choice(("==", "!=", "<", "<=", ">", ">="))
        return (f"{self.value('any', depth + 1)} {op} "
                f"{self.value('any', depth + 1)}")

    def _v_bool_logic(self, depth: int) -> str:
        op = self.rng.choice(("and", "or"))
        return (f"{self.value('bool', depth + 1)} {op} "
                f"{self.value('bool', depth + 1)}")

    def _v_bool_contains(self, depth: int) -> str:
        if self.rng.random() < 0.5:
            haystack = self.rng.choice(("list", "str", "map"))
            return (f"contains({self.value('any', depth + 1)}, "
                    f"{self.value(haystack, depth + 1)})")
        haystack = self.rng.choice(("list", "str"))
        return (f"{self.value('any', depth + 1)} in "
                f"{self.value(haystack, depth + 1)}")

    def _v_bool_member(self, depth: int) -> str:
        name, kinds = self.rng.choice((("contains", ("any",)),
                                       ("has", ("str",)),
                                       ("starts_with", ("str",)),
                                       ("index", ("any",))))
        args = ", ".join(self.arg(k, depth) for k in kinds)
        return f"{self.value('any', depth + 1)}.{name}({args})"


# ----------------------------------------------------------- defect recipes
# Each recipe turns a valid program into one that must be *rejected*.  They are
# deterministic on purpose: `defect_sources()` feeds them to the test corpus,
# which pins that malformed input is rejected rather than crashing.
_DEFECT_BASE = 'let total = 1\nlet label = "run"\nemit total + 1'

_DEFECTS: Tuple[Tuple[str, Callable[[random.Random, str], str]], ...] = (
    ("dangling operator", lambda rng, src: src + " +"),
    ("dangling let", lambda rng, src: src + "\nlet"),
    ("stray closer", lambda rng, src: src + "\n}"),
    ("unterminated string", lambda rng, src: src + '\nemit "abc'),
    ("unterminated escape", lambda rng, src: src + '\nemit "\\'),
    ("unterminated interpolation", lambda rng, src: src + '\nemit "{1 + '),
    ("empty interpolation", lambda rng, src: src + '\nemit "{}"'),
    ("blank interpolation", lambda rng, src: src + '\nemit "{ }"'),
    ("malformed number", lambda rng, src: src + "\nemit 0x"),
    ("keyword as name", lambda rng, src: src + "\nlet = 1"),
    ("member without name", lambda rng, src: src + "\nemit 1."),
    ("operator sandwich", lambda rng, src: src + "\nemit 1 + * 2"),
    ("unclosed block", lambda rng, src: "if 1 {\n" + src),
    ("deep unbalanced nesting", lambda rng, src: src + "\nemit " + "(" * 20 + "1"),
    # These two exhaust the interpreter stack in the *parser*. They used to
    # escape as `RecursionError` (a host exception); the parser now reports its
    # own limit, so they belong with the other rejections. The compiler has the
    # same guard for wide (not deep) chains — that one raises
    # `JockyCompileError`, so it is pinned in `tests/test_language.py` rather
    # than in this syntax-only catalogue.
    ("stack-deep parens", lambda rng, src: src + "\nemit " + "(" * 200 + "1" + ")" * 200),
    ("stack-deep list", lambda rng, src: src + "\nemit " + "[" * 200 + "1" + "]" * 200),
    ("truncated with dangling operator",
     lambda rng, src: src[:rng.randrange(1, len(src))] + " +"),
)


def defect_sources(base: str = _DEFECT_BASE) -> List[str]:
    """One guaranteed-malformed program per recipe in ``_DEFECTS``."""
    rng = random.Random(0)
    return [apply(rng, base) for _, apply in _DEFECTS]


# Recipe names in the order ``defect_sources()`` returns them.
DEFECT_NAMES: Tuple[str, ...] = tuple(name for name, _ in _DEFECTS)


# --------------------------------------------------------------- generation
def generate(seed: int, count: int) -> List[str]:
    """``count`` programs for ``seed`` — identical today and next month.

    The historical reproducers come first so *every* corpus carries them; the
    remainder is drawn from a fresh per-seed RNG (program order included).
    """
    rng = random.Random(seed)
    programs = list(HISTORICAL_REPRODUCERS[:count])
    while len(programs) < count:
        programs.append(_Gen(rng).program())
    return programs


# ------------------------------------------------------------------ checking
def _run_case(source: str, wall_ms: float = WALL_MS,
              max_steps: int = MAX_STEPS) -> Tuple[str, str, str]:
    """Compile and run one program; classify whatever leaves the boundary.

    Returns ``("ok", "", "")``, ``("jockey", "<Type>: <message>", "")`` for a
    ``JockyError`` — the documented outcome for bad input — or ``("host", …)``
    with a traceback tail for an exception the runtime never promised to raise.
    """
    try:
        compile_source(source)
        run_source(source, wall_clock_ms=wall_ms, max_steps=max_steps)
    except JockyError as exc:
        return "jockey", f"{type(exc).__name__}: {exc}", ""
    except Exception as exc:                 # noqa: BLE001 - this is the bug
        tail = "\n".join(traceback.format_exc().strip().splitlines()[-6:])
        return "host", f"{type(exc).__name__}: {exc}", tail
    return "ok", "", ""


_POSITION_RE = re.compile(r" \(line \d+, col \d+\)")
_QUOTED_RE = re.compile(r"'[^']*'")
_NUMBER_RE = re.compile(r"\d+")


def _normalise(message: str) -> str:
    """Collapse a message into a histogram bucket (positions and values vary)."""
    text = _POSITION_RE.sub("", message)
    text = _QUOTED_RE.sub("'…'", text)
    return _NUMBER_RE.sub("N", text)


def _trips(source: str, kind: str, wall_ms: float,
           max_steps: int = MAX_STEPS) -> bool:
    """True when ``source`` still escapes as host exception type ``kind``."""
    status, error, _ = _run_case(source, wall_ms, max_steps)
    return status == "host" and error.split(":")[0] == kind


def _shrink(source: str, kind: str, wall_ms: float, max_steps: int,
            budget: int) -> str:
    """Drop lines, then characters, while ``kind`` keeps escaping."""
    best = source
    spent = 0

    def still_fails(candidate: str) -> bool:
        nonlocal spent
        spent += 1
        return _trips(candidate, kind, wall_ms, max_steps)

    for splitter, joiner in ((str.splitlines, "\n"), (list, "")):
        units: List[str] = splitter(best)
        index = 0
        while index < len(units) and spent < budget:
            trial = units[:index] + units[index + 1:]
            candidate = joiner.join(trial)
            if candidate.strip() and still_fails(candidate):
                units = trial
                best = candidate
            else:
                index += 1
    return best


def minimise(source: str, wall_ms: float = WALL_MS,
             max_steps: int = MAX_STEPS, budget: int = 400) -> str:
    """Smallest program that still raises the same *kind* of host exception."""
    status, error, _ = _run_case(source, wall_ms, max_steps)
    if status != "host":
        return source
    kind = error.split(":")[0]
    best = _shrink(source, kind, wall_ms, max_steps, budget)
    # The passes above cannot strip the last line or character of a one-line
    # program, so try the stripped forms explicitly.
    stripped = best.strip()
    for candidate in (stripped, stripped.splitlines()[-1] if stripped else ""):
        if candidate and _trips(candidate, kind, wall_ms, max_steps):
            return candidate
    return best


_MINIMISED_FINDINGS = 5


def fuzz(count: int = 500, seed: int = 0, wall_ms: float = WALL_MS) -> Dict[str, Any]:
    """Run ``count`` generated programs; report anything that escapes.

    ``host_exceptions`` entries carry the minimised program and a traceback
    tail.  Only the first ``_MINIMISED_FINDINGS`` findings are shrunk — a
    front end that is broken everywhere would otherwise pay for shrinking
    thousands of samples.
    """
    programs = generate(seed, count)
    host_exceptions: List[Dict[str, str]] = []
    buckets: Dict[str, Dict[str, Any]] = {}
    ok = 0
    for source in programs:
        status, error, tail = _run_case(source, wall_ms)
        if status == "ok":
            ok += 1
        elif status == "jockey":
            bucket = buckets.setdefault(_normalise(error),
                                        {"error": _normalise(error), "count": 0,
                                         "example": source})
            bucket["count"] += 1
        else:
            kind = error.split(":")[0]
            minimised = (minimise(source, wall_ms)
                         if len(host_exceptions) < _MINIMISED_FINDINGS else source)
            if not _trips(minimised, kind, wall_ms):
                # Shrinking can strip a stack-depth-sensitive failure (a
                # RecursionError) past the point where it still trips from
                # here; report the input as generated rather than a sample
                # that no longer reproduces.
                minimised = source
            host_exceptions.append({"error": error, "source": minimised,
                                    "traceback_tail": tail})
    return {
        "generated": len(programs),
        "ok": ok,
        "host_exceptions": host_exceptions,
        "jockey_errors": sorted(buckets.values(),
                                key=lambda bucket: (-bucket["count"], bucket["error"])),
    }


def describe(report: Dict[str, Any]) -> Sequence[str]:
    """Human summary of a ``fuzz`` report, for interactive use."""
    lines = [f"generated={report['generated']} ok={report['ok']} "
             f"host_exceptions={len(report['host_exceptions'])}"]
    lines.extend(f"  {entry['count']:5d}  {entry['error']}"
                 for entry in report["jockey_errors"])
    return lines
