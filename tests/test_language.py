"""
Language semantics tests.

These pin *behaviour*, not implementation: each test would fail if the
compiler or VM changed what a script observes.  Coverage focuses on the places
where a tree-walking shortcut usually breaks — operator precedence, short
circuit evaluation, closure cell sharing, loop control flow inside protected
regions, error propagation and the interpreter's safety limits.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky.errors import JockyError  # noqa: E402
from jocky.lang.compiler import Proto, Program  # noqa: E402
from jocky.lang.vm import VM  # noqa: E402
from jocky.rt.builtins import default_natives  # noqa: E402
from jocky.runner import compile_source  # noqa: E402


def run(source: str, **kwargs):
    """Execute a script with the full runtime and return the RunResult."""
    vm = VM(natives=default_natives(), **{k: v for k, v in kwargs.items()
                                          if k in ("max_steps", "max_frames")})
    return vm.run(compile_source(source), wall_clock_ms=kwargs.get("wall_clock_ms", 20_000))


def findings(source: str):
    result = run(source)
    assert not result.errors, result.errors
    return result.findings


def evaluate(expression: str):
    result = run(f"emit ({expression})")
    assert not result.errors, result.errors
    return result.findings[0]


# ----------------------------------------------------------------- arithmetic
@pytest.mark.parametrize("expression,expected", [
    ("2 + 3 * 4", 14),
    ("(2 + 3) * 4", 20),
    ("10 - 4 - 3", 3),
    ("20 / 4", 5.0),
    ("7 % 3", 1),
    ("-5 + 3", -2),
    ("2 * -3", -6),
    ("1 + 2 * 3 - 4 / 2", 5.0),
])
def test_arithmetic_precedence(expression, expected):
    assert evaluate(expression) == expected


def test_string_concatenation_and_interpolation():
    assert evaluate('"a" + "b"') == "ab"
    assert evaluate('"n=" + str(2 + 3)') == "n=5"
    assert findings('let x = 7\nemit "x={x} ok"') == ["x=7 ok"]


def test_comparison_and_equality():
    assert evaluate("3 > 2") is True
    assert evaluate("2 >= 3") is False
    assert evaluate('"abc" < "abd"') is True
    assert evaluate("[1, 2] == [1, 2]") is True
    assert evaluate("1 in [1, 2, 3]") is True
    assert evaluate('"ell" in "hello"') is True


# ------------------------------------------------------------------- control
def test_if_elif_else_selection():
    source = """
    let pick = fn(n) {
      if n == 1 { return "one" }
      elif n == 2 { return "two" }
      else { return "many" }
    }
    emit pick(1)
    emit pick(2)
    emit pick(9)
    """
    assert findings(source) == ["one", "two", "many"]


def test_while_break_continue():
    source = """
    let i = 0
    let seen = []
    while i < 6 {
      set i = i + 1
      if i == 2 { continue }
      if i == 5 { break }
      seen.push(i)
    }
    emit seen
    """
    assert findings(source) == [[1, 3, 4]]


def test_short_circuit_does_not_evaluate_rhs():
    # `error()` raises, so reaching the right-hand side would surface an error.
    assert findings('emit (false and error("boom"))') == [False]
    assert findings('emit (true or error("boom"))') == [True]


@pytest.mark.parametrize("iterable,expected", [
    ("[1, 2, 3]", [1, 2, 3]),
    ('"ab"', ["a", "b"]),
])
def test_for_iteration(iterable, expected):
    assert findings(f"for x in {iterable} {{ emit x }}") == expected


def test_map_iteration_yields_key_value_pairs():
    source = """
    let m = {"a": 1, "b": 2}
    for pair in m { emit pair[0] + "=" + str(pair[1]) }
    """
    assert sorted(findings(source)) == ["a=1", "b=2"]


# ----------------------------------------------------------------- functions
def test_function_without_return_yields_nil():
    assert findings("fn nothing() { let x = 1 }\nemit nothing()") == [None]


def test_recursion():
    source = """
    fn fact(n) { if n <= 1 { return 1 }
      return n * fact(n - 1) }
    emit fact(6)
    """
    assert findings(source) == [720]


def test_arity_mismatch_is_an_error():
    result = run("fn f(a, b) { return a }\nemit f(1)")
    assert result.errors and "expects 2 argument" in result.errors[0]


def test_undefined_name_is_an_error():
    result = run("emit not_defined_anywhere")
    assert result.errors and "undefined name" in result.errors[0]


def test_index_out_of_range_is_an_error():
    result = run("let xs = [1]\nemit xs[4]")
    assert result.errors and "out of range" in result.errors[0]


def test_type_error_reports_operands():
    result = run("emit nil + 1")
    assert result.errors and "cannot add" in result.errors[0]


# ------------------------------------------------------------------ closures
def test_closure_shares_mutable_state():
    source = """
    fn counter() {
      let c = 0
      return fn() { set c = c + 1
        return c }
    }
    let c1 = counter()
    let c2 = counter()
    emit [c1(), c1(), c1(), c2()]
    """
    assert findings(source) == [[1, 2, 3, 1]]


def test_closure_captures_nested_scope():
    source = """
    fn outer() {
      let n = 100
      fn inner() {
        let k = 5
        return fn() { return n + k }
      }
      return inner()
    }
    emit outer()()
    """
    assert findings(source) == [105]


def test_two_closures_share_one_variable():
    source = """
    fn pair() {
      let shared = 0
      let inc = fn() { set shared = shared + 1
        return shared }
      let get = fn() { return shared }
      return [inc, get]
    }
    let p = pair()
    emit p[1]()
    emit p[0]()
    emit p[1]()
    """
    assert findings(source) == [0, 1, 1]


# ---------------------------------------------------------------- collections
def test_list_and_map_methods():
    source = """
    let xs = [3, 1, 2]
    xs.push(4)
    let ordered = xs.sort()
    emit ordered
    emit xs
    emit xs.len()
    emit xs.contains(2)
    emit xs.join("-")
    emit [1, 2, 2, 3].unique()
    let m = {"k": 1}
    emit m.get("k")
    emit m.has("nope")
    emit m.keys()
    emit contains("k", m)
    """
    assert findings(source) == [
        [1, 2, 3, 4],        # sort returns an ordered copy
        [3, 1, 2, 4],        # …and leaves the original alone
        4, True, "3-1-2-4", [1, 2, 3], 1, False, ["k"], True,
    ]


def test_string_methods():
    source = """
    emit "Hello World".lower()
    emit "  pad  ".strip()
    emit "a,b,c".split(",")
    emit "abc".starts_with("ab")
    emit "abc".substr(1)
    emit "abcabc".replace("a", "z")
    """
    assert findings(source) == [
        "hello world", "pad", ["a", "b", "c"], True, "bc", "z bcz bc".replace(" ", ""),
    ]


def test_higher_order_builtins():
    source = """
    let xs = [1, 2, 3, 4, 5]
    emit transform(xs, fn(n) { return n * n })
    emit filter(xs, fn(n) { return n % 2 == 1 })
    emit count(xs, fn(n) { return n > 3 })
    emit sort_by(["bb", "a", "ccc"], fn(s) { return s.len() })
    """
    assert findings(source) == [[1, 4, 9, 16, 25], [1, 3, 5], 2, ["a", "bb", "ccc"]]


# ---------------------------------------------------------------- error paths
def test_division_by_zero_is_catchable():
    source = """
    try { let bad = 1 / 0 } catch e { emit "caught: {e}" }
    """
    assert findings(source) == ["caught: division by zero"]


def test_native_error_is_catchable():
    assert findings('try { error("boom") } catch e { emit e }') == ["boom"]


def test_uncaught_error_stops_the_program():
    result = run('emit "before"\nemit 1 / 0\nemit "after"')
    assert result.errors and result.findings == ["before"]


def test_try_inside_loop_catches_each_iteration():
    source = """
    let caught = 0
    for n in [1, 0, 2, 0] {
      try { let v = 10 / n } catch e { set caught = caught + 1 }
    }
    emit caught
    """
    assert findings(source) == [2]


def test_error_inside_function_propagates_to_caller_handler():
    source = """
    fn boom() { return 1 / 0 }
    try { boom() } catch e { emit "handled" }
    """
    assert findings(source) == ["handled"]


# --------------------------------------------------------------------- limits
def test_step_budget_stops_infinite_loop():
    result = run("while true { let x = 1 }", max_steps=5_000)
    assert result.truncated and any("step budget" in e for e in result.errors)


def test_call_depth_limit_is_reported():
    result = run("fn f(n) { return f(n + 1) }\nemit f(0)", max_frames=32)
    assert any("call depth" in e for e in result.errors)


@pytest.mark.parametrize("target,fragment", [
    (-1, "outside"),
    (3, "outside"),
    (10 ** 9, "outside"),
    ("nowhere", "integer"),
])
def test_indirect_jump_target_is_checked(target, fragment):
    """``JMPI`` is the one opcode whose destination is a runtime value.

    The compiler never emits it, so only a hand-built proto or an artifact can
    produce one -- and an artifact's constant pool is attacker-influenceable,
    which is exactly why the VM has to grade the value itself rather than trust
    it: an unchecked target is a read outside ``proto.code``, and a negative
    one wraps to the end of the code instead of failing.
    """
    program = Program(
        main=Proto(name="<main>", code=[("CONST", 0), ("JMPI", None), ("HALT", None)]),
        consts=[target],
    )
    result = VM(natives=default_natives()).run(program, wall_clock_ms=5_000)
    assert result.errors, f"JMPI to {target!r} was not reported"
    assert fragment in result.errors[0], result.errors
    assert not result.truncated


# ------------------------------------------------------------------ output API
def test_emit_and_print_are_separate_channels():
    result = run('print("to stdout")\nemit {"kind": "finding"}')
    assert result.output == ["to stdout"]
    assert result.findings == [{"kind": "finding"}]


def test_wall_clock_budget_is_enforced():
    result = run("while true { let x = 1 }", wall_clock_ms=50)
    assert result.truncated


def test_a_long_native_cannot_silently_overrun_the_budget():
    """Regression: the deadline was sampled only between VM steps, so one long
    native ran past the budget and still reported truncated: false."""
    result = run('emit ioc.match({"names": ["nothing"]}, "/usr", 4000)', wall_clock_ms=5)
    assert result.truncated, "a native that outlives the budget must be reported"


# ------------------------------------------------------- front-end regressions
def test_trailing_zero_literal_parses():
    """Regression: `0` at end of input crashed the lexer with a KeyError."""
    assert findings("let x = 0\nemit x") == [0]
    assert findings('emit "{0}"') == ["0"]
    assert findings("emit 0") == [0]


def test_constant_pool_keeps_literal_types_distinct():
    """Regression: 1, 1.0 and true used to collapse into one pool entry."""
    result = run("emit 1.0\nemit 1\nemit true\nemit false\nemit 0")
    assert not result.errors, result.errors
    assert result.findings == [1.0, 1, True, False, 0]
    assert [type(value).__name__ for value in result.findings] == [
        "float", "int", "bool", "bool", "int",
    ]


def test_zero_does_not_become_false():
    result = run("let w = 0\nlet b = false\nemit [type(w), type(b)]")
    assert result.findings == [["int", "bool"]]


def test_unknown_escape_keeps_its_backslash():
    """Detection patterns must survive verbatim: '\\d+' may not become 'd+'."""
    assert findings('emit "\\d+ \\w*"') == ["\\d+ \\w*"]
    assert findings('emit "line\\nnext"') == ["line\nnext"]
    assert findings('emit "tab\\there"') == ["tab\there"]


@pytest.mark.parametrize("source", [
    "(" * 200 + "1" + ")" * 200,              # nested groups: the parser recurses
    "[" * 200 + "1" + "]" * 200,              # nested list literals
    "-" * 4000 + "1",                         # a very long unary chain
    '"' + '"{ ' * 200 + "1" + ' }"' * 200 + '"',   # nested interpolations re-lex
    "1" + ".to_str()" * 600,                  # wide, not deep: the compiler recurses
])
def test_deeply_nested_source_is_reported_not_crashed(source):
    """Regression: these escaped as the host's ``RecursionError``, so a script
    (or an artifact's source) could take the process down with a traceback
    instead of a diagnostic."""
    with pytest.raises(JockyError) as excinfo:
        compile_source(source)
    assert "too deeply" in str(excinfo.value)
    assert not isinstance(excinfo.value, RecursionError)


def test_break_in_a_nested_for_loop_ends_only_that_loop():
    """Regression: ``break`` inside a nested ``for`` left the inner iterator on
    the operand stack.

    ITER_NEXT pops the iterator when a loop ends by exhaustion; leaving by
    ``break`` jumped to the loop end without popping, so the *enclosing* loop's
    ITER_NEXT found the inner iterator at the top of the stack and replayed the
    inner sequence. The outer variable was rebound to the inner values and the
    outer loop never terminated — it ran until the wall-clock budget stopped it,
    which is why this is pinned by behaviour and not by a peek at the stack.
    """
    result = run("""
let seen = []
for a in ["A1", "A2", "A3"] {
  for b in [1, 2, 3] {
    if b == 2 { break }
    seen.push(str(a) + ":" + str(b))
  }
  seen.push("after-" + str(a))
}
emit seen
""")
    assert result.errors == [], result.errors
    # One inner iteration per outer pass (b==2 breaks), then the outer tail.
    assert result.findings[0] == [
        "A1:1", "after-A1", "A2:1", "after-A2", "A3:1", "after-A3"]


def test_break_in_a_nested_while_inside_a_for_does_not_unbalance_the_stack():
    """A ``while`` keeps nothing on the stack, so its ``break`` must not pop.

    The mirror of the test above: the fix has to distinguish the two loop kinds,
    and a blanket POP would break this one by popping the enclosing ``for``'s
    iterator instead.
    """
    result = run("""
let seen = []
for a in [1, 2] {
  let n = 0
  while true {
    set n = n + 1
    if n == 2 { break }
  }
  seen.push(str(a) + "=" + str(n))
}
emit seen
""")
    assert result.errors == [], result.errors
    assert result.findings[0] == ["1=2", "2=2"]


def test_break_out_of_three_nested_loops_returns_to_the_right_level():
    """Each ``break`` must pop exactly its own loop's iterator, no more."""
    result = run("""
let trace = []
for a in [1, 2] {
  for b in [1, 2] {
    for c in [1, 2] {
      trace.push(str(a) + str(b) + str(c))
      break
    }
    trace.push("mid" + str(a) + str(b))
    break
  }
  trace.push("outer" + str(a))
}
emit trace
""")
    assert result.errors == [], result.errors
    assert result.findings[0] == ["111", "mid11", "outer1", "211", "mid21", "outer2"]
