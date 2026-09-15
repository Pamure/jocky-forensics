"""
JOCKY virtual machine.

A small stack machine.  Values are Python natives plus two wrappers:

* :class:`JFn`     — a closure (proto + captured values),
* :class:`NativeFn`— a host function exposed to scripts (``proc.list`` ...).

Numbers are int/float, strings are str, lists are list and maps are dict;
scripts can therefore be written without any boxing ceremony while the VM
still keeps method dispatch (``p.pid``, ``s.upper()``) explicit.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from jocky.errors import JockyError, JockyRuntimeError
from jocky.lang.compiler import Proto, Program


class JockyLimitError(JockyError):
    """Uncatchable safety limit (step budget, frame depth, wall clock)."""


@dataclass
class Frame:
    proto: Proto
    locals: List[Any] = field(default_factory=list)
    stack: List[Any] = field(default_factory=list)
    ip: int = 0
    handlers: List[Tuple[int, int, int, int, int]] = field(default_factory=list)
    # handler entries: (stack_depth, start_ip, end_ip, handler_ip, slot)


@dataclass
class JFn:
    proto: Proto
    captures: List[Any] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.proto.name


class NativeFn:
    """A host function callable from scripts."""

    __slots__ = ("name", "fn", "min_args", "max_args")

    def __init__(self, name: str, fn: Callable[[Any, List[Any]], Any],
                 min_args: int = 0, max_args: Optional[int] = None):
        self.name = name
        self.fn = fn
        self.min_args = min_args
        self.max_args = max_args

    def __call__(self, vm: "VM", args: List[Any]) -> Any:
        return self.fn(vm, args)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<native {self.name}>"


class JIter:
    """Iterator handle held on the operand stack by ``for`` loops."""

    __slots__ = ("items", "index")

    def __init__(self, items: List[Any]):
        self.items = items
        self.index = 0


def truthy(value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0
    if isinstance(value, (str, list, dict, tuple)):
        return len(value) > 0
    return True


def to_str(value: Any) -> str:
    if value is None:
        return "nil"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return value
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return repr(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, (list, dict)):
        return json.dumps(to_plain(value), ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, JFn):
        return f"<fn {value.name}>"
    if isinstance(value, NativeFn):
        return f"<native {value.name}>"
    return str(value)


def to_plain(value: Any) -> Any:
    """Convert a script value into JSON-serialisable host data."""
    if isinstance(value, JFn):
        return f"<fn {value.name}>"
    if isinstance(value, NativeFn):
        return f"<native {value.name}>"
    if isinstance(value, JIter):
        return "<iter>"
    if isinstance(value, list):
        return [to_plain(v) for v in value]
    if isinstance(value, dict):
        return {str(k): to_plain(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [to_plain(v) for v in value]
    if isinstance(value, float) and value.is_integer():
        return value
    return value


# --------------------------------------------------------------------- results
@dataclass
class RunResult:
    findings: List[Any] = field(default_factory=list)
    output: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    checks: List[Dict[str, Any]] = field(default_factory=list)   # assert/expect results
    denials: List[Dict[str, Any]] = field(default_factory=list)  # refused capabilities
    permissions: Dict[str, Any] = field(default_factory=dict)    # what this run was allowed
    steps: int = 0
    native_calls: int = 0
    duration_ms: float = 0.0
    truncated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findings": to_plain(self.findings),
            "output": list(self.output),
            "errors": list(self.errors),
            "checks": list(self.checks),
            "denials": list(self.denials),
            "permissions": dict(self.permissions),
            "steps": self.steps,
            "native_calls": self.native_calls,
            "duration_ms": round(self.duration_ms, 3),
            "truncated": self.truncated,
        }


class VM:
    """Executes a compiled :class:`Program`."""

    def __init__(self, natives: Optional[Dict[str, Any]] = None,
                 max_steps: int = 20_000_000, max_frames: int = 256):
        self.max_steps = max_steps
        self.max_frames = max_frames
        self.native_calls = 0
        self.steps = 0
        self.program: Optional[Program] = None
        self.globals: Dict[str, Any] = dict(natives or {})
        self.findings: List[Any] = []
        self.output: List[str] = []
        self.frames: List[Frame] = []
        self.ctx: Dict[str, Any] = {}
        self._deadline: Optional[float] = None
        self._frame_floor: int = 0
        self._ops: Dict[str, Callable[[Frame, Any], None]] = {
            "CONST": self._op_const,
            "LOADL": self._op_loadl,
            "STOREL": self._op_storel,
            "LOAD_CELL": self._op_load_cell,
            "STORE_CELL": self._op_store_cell,
            "PUSH_CELL": self._op_push_cell,
            "LOADG": self._op_loadg,
            "STOREG": self._op_storeg,
            "POP": lambda f, a: f.stack.pop(),
            "DUP": self._op_dup,
            "ADD": self._binop(self._add),
            "SUB": self._binop(self._sub),
            "MUL": self._binop(self._mul),
            "DIV": self._binop(self._div),
            "MOD": self._binop(self._mod),
            "EQ": self._binop(lambda a, b: a == b),
            "NE": self._binop(lambda a, b: a != b),
            "LT": self._binop(self._cmp(lambda a, b: a < b, "<")),
            "LE": self._binop(self._cmp(lambda a, b: a <= b, "<=")),
            "GT": self._binop(self._cmp(lambda a, b: a > b, ">")),
            "GE": self._binop(self._cmp(lambda a, b: a >= b, ">=")),
            "IN": self._binop(self._contains),
            "NEG": self._op_neg,
            "NOT": self._op_not,
            "JMP": self._op_jmp,
            "JMPF": self._op_jmpf,
            "JMPT": self._op_jmpt,
            "CALL": self._op_call,
            "RET": self._op_ret,
            "MK_LIST": self._op_mk_list,
            "MK_MAP": self._op_mk_map,
            "GET_IDX": self._op_get_idx,
            "SET_IDX": self._op_set_idx,
            "GET_MEM": self._op_get_mem,
            "SET_MEM": self._op_set_mem,
            "MK_FN": self._op_mk_fn,
            "ITER_INIT": self._op_iter_init,
            "ITER_NEXT": self._op_iter_next,
            "EMIT": self._op_emit,
            "HALT": self._op_halt,
            "TRY_ENTER": self._op_try_enter,
            "TRY_EXIT": self._op_try_exit,
        }
        for nop in ("NOP0", "NOP1", "NOP2", "NOP3", "NOP4", "NOP5", "NOP6", "NOP7"):
            self._ops[nop] = lambda f, a: None

    # ------------------------------------------------------------------ entry
    def run(self, program: Program, wall_clock_ms: Optional[float] = None) -> RunResult:
        self.program = program
        self.steps = 0
        self.native_calls = 0
        self.findings = []
        self.output = []
        self.frames = [self._new_frame(program.main, [None] * program.main.nlocals)]
        errors: List[str] = []
        truncated = False
        started = time.perf_counter()
        try:
            self._loop(started, wall_clock_ms)
        except JockyLimitError as exc:
            errors.append(str(exc))
            truncated = True
        except JockyRuntimeError as exc:
            errors.append(str(exc))
        duration = (time.perf_counter() - started) * 1000.0
        return RunResult(
            findings=list(self.findings),
            output=list(self.output),
            errors=errors,
            checks=list(self.ctx.get("checks", [])),
            denials=list(self.ctx.get("denials", [])),
            permissions={
                "granted": sorted((self.ctx.get("policy") or {}).get("allow") or []),
                **({"sandbox": self.ctx["sandbox"]} if "sandbox" in self.ctx else {}),
            },
            steps=self.steps,
            native_calls=self.native_calls,
            duration_ms=duration,
            truncated=truncated,
        )

    def _loop(self, started: float, wall_clock_ms: Optional[float]) -> None:
        self._deadline = None if wall_clock_ms is None else started + wall_clock_ms / 1000.0
        while self.frames:
            frame = self.frames[-1]
            if frame.ip >= len(frame.proto.code):
                self._pop_frame(None)          # implicit nil return
                continue
            self._run_one(frame)

    def _run_one(self, frame: Frame) -> None:
        code = frame.proto.code
        op, arg = code[frame.ip]
        frame.ip += 1
        self.steps += 1
        if self.steps > self.max_steps:
            raise JockyLimitError(f"step budget exceeded ({self.max_steps} instructions)")
        if self._deadline is not None and (self.steps & 0x3FF) == 0:
            if time.perf_counter() > self._deadline:
                raise JockyLimitError("wall-clock budget exceeded")
        try:
            if op == "CONST":
                frame.stack.append(self.program.consts[arg])
                return
            handler = self._ops.get(op)
            if handler is None:
                raise JockyRuntimeError(f"invalid opcode {op!r}")
            handler(frame, arg)
        except JockyLimitError:
            raise
        except JockyRuntimeError as exc:
            self._unwind(exc)
        except RecursionError:
            raise JockyLimitError("host recursion limit reached")
        except ZeroDivisionError:
            self._unwind(JockyRuntimeError("division by zero"))
        except Exception as exc:  # host errors become script-visible errors
            self._unwind(JockyRuntimeError(f"{type(exc).__name__}: {exc}"))

    def _pop_frame(self, value: Any) -> None:
        self.frames.pop()
        if self.frames:
            self.frames[-1].stack.append(value)

    def _check_deadline(self) -> None:
        """Raise if the wall-clock budget has already elapsed (uncatchable)."""
        if self._deadline is not None and time.perf_counter() > self._deadline:
            raise JockyLimitError("wall-clock budget exceeded")

    def call_value(self, fn: Any, args: List[Any]) -> Any:
        """Call a script function or native from host code.

        Used by higher-order natives (``map``, ``filter``, ``sort``) so they
        can invoke JOCKY closures without leaving the VM.
        """
        if isinstance(fn, NativeFn):
            self.native_calls += 1
            return fn(self, args)
        if not isinstance(fn, JFn):
            raise JockyRuntimeError(f"{type(fn).__name__} is not callable")
        proto = fn.proto
        if len(args) != len(proto.params):
            raise JockyRuntimeError(
                f"{fn.name}() expects {len(proto.params)} argument(s), got {len(args)}"
            )
        if len(self.frames) >= self.max_frames:
            raise JockyLimitError(f"call depth exceeded ({self.max_frames} frames)")
        depth = len(self.frames)
        previous_floor = self._frame_floor
        self._frame_floor = depth
        try:
            self.frames.append(self._new_frame(proto, list(fn.captures) + list(args)))
            while len(self.frames) > depth:
                frame = self.frames[-1]
                if frame.ip >= len(frame.proto.code):
                    self._pop_frame(None)
                    continue
                self._run_one(frame)
        finally:
            self._frame_floor = previous_floor
            del self.frames[depth:]           # discard unwound callee frames
        if self.frames and self.frames[-1].stack:
            return self.frames[-1].stack.pop()
        return None

    @staticmethod
    def _new_frame(proto: Proto, locals_list: List[Any]) -> Frame:
        """Build a frame, padding locals and boxing cell slots."""
        if proto.nlocals > len(locals_list):
            locals_list = list(locals_list) + [None] * (proto.nlocals - len(locals_list))
        for slot in proto.cell_slots:
            # slots below ncaptures already hold cells handed over by the parent
            if slot >= proto.ncaptures and slot < len(locals_list):
                locals_list[slot] = [locals_list[slot]]
        return Frame(proto=proto, locals=locals_list)

    def _unwind(self, exc: JockyRuntimeError) -> None:
        """Route a runtime error to the innermost active try/catch, if any.

        The handler may live in a *caller*: an error raised inside a function
        has to discard that function's frames until a frame with a matching
        protected region is found.  ``_frame_floor`` stops the walk at a
        host-side native boundary (``call_value``) so the frame that owns the
        handler performs the jump itself.
        """
        while True:
            if not self.frames or len(self.frames) <= self._frame_floor:
                raise exc
            frame = self.frames[-1]
            ip = frame.ip - 1
            while frame.handlers:
                depth, start_ip, end_ip, handler_ip, slot = frame.handlers[-1]
                if start_ip <= ip < end_ip:
                    del frame.stack[depth:]
                    frame.stack.append(str(exc))
                    frame.ip = handler_ip
                    frame.handlers.pop()
                    return
                frame.handlers.pop()
            self.frames.pop()                 # no handler here: unwind one level

    # ------------------------------------------------------------- stack utils
    def _pop2(self, frame: Frame) -> Tuple[Any, Any]:
        b = frame.stack.pop()
        a = frame.stack.pop()
        return a, b

    def _binop(self, fn: Callable[[Any, Any], Any]):
        def op(frame: Frame, arg: Any) -> None:
            a, b = self._pop2(frame)
            frame.stack.append(fn(a, b))
        return op

    def _cmp(self, fn: Callable[[Any, Any], bool], symbol: str):
        def compare(a: Any, b: Any) -> bool:
            if isinstance(a, (int, float)) and isinstance(b, (int, float)):
                return fn(a, b)
            if isinstance(a, str) and isinstance(b, str):
                return fn(a, b)
            raise JockyRuntimeError(
                f"cannot compare {type(a).__name__} {symbol} {type(b).__name__}"
            )
        return compare

    def _add(self, a: Any, b: Any) -> Any:
        if isinstance(a, str) or isinstance(b, str):
            return to_str(a) + to_str(b)
        if isinstance(a, list) and isinstance(b, list):
            return a + b
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            return a + b
        raise JockyRuntimeError(f"cannot add {type(a).__name__} and {type(b).__name__}")

    def _sub(self, a: Any, b: Any) -> Any:
        for value, other in ((a, b),):
            if not isinstance(value, (int, float)) or not isinstance(other, (int, float)):
                raise JockyRuntimeError("'-' needs two numbers")
        return a - b

    def _mul(self, a: Any, b: Any) -> Any:
        if isinstance(a, str) and isinstance(b, int):
            return a * max(0, b)
        if isinstance(a, list) and isinstance(b, int):
            return a * max(0, b)
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            return a * b
        raise JockyRuntimeError(f"cannot multiply {type(a).__name__} by {type(b).__name__}")

    def _div(self, a: Any, b: Any) -> Any:
        if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
            raise JockyRuntimeError("'/' needs two numbers")
        if b == 0:
            raise JockyRuntimeError("division by zero")
        return a / b

    def _mod(self, a: Any, b: Any) -> Any:
        if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
            raise JockyRuntimeError("'%' needs two numbers")
        if b == 0:
            raise JockyRuntimeError("modulo by zero")
        return a % b

    def _contains(self, needle: Any, haystack: Any) -> bool:
        if isinstance(haystack, str):
            return to_str(needle) in haystack
        if isinstance(haystack, list):
            return any(item == needle for item in haystack)
        if isinstance(haystack, dict):
            return to_str(needle) in haystack
        raise JockyRuntimeError(f"'in' needs a string, list or map, got {type(haystack).__name__}")

    # --------------------------------------------------------------- opcodes
    def _op_const(self, frame: Frame, arg: Any) -> None:  # handled inline
        frame.stack.append(self.program.consts[arg])

    def _op_loadl(self, frame: Frame, arg: Any) -> None:
        try:
            frame.stack.append(frame.locals[arg])
        except IndexError:
            raise JockyRuntimeError(f"local slot {arg} out of range")

    def _op_storel(self, frame: Frame, arg: Any) -> None:
        value = frame.stack.pop()
        if arg >= len(frame.locals):
            raise JockyRuntimeError(f"local slot {arg} out of range")
        frame.locals[arg] = value

    def _op_loadg(self, frame: Frame, arg: Any) -> None:
        name = self.program.names[arg]
        if name not in self.globals:
            raise JockyRuntimeError(f"undefined name {name!r}")
        frame.stack.append(self.globals[name])

    def _op_storeg(self, frame: Frame, arg: Any) -> None:
        name = self.program.names[arg]
        self.globals[name] = frame.stack.pop()

    def _op_load_cell(self, frame: Frame, arg: Any) -> None:
        cell = frame.locals[arg] if arg < len(frame.locals) else None
        if not isinstance(cell, list) or len(cell) != 1:
            raise JockyRuntimeError(f"local slot {arg} is not a capture cell")
        frame.stack.append(cell[0])

    def _op_store_cell(self, frame: Frame, arg: Any) -> None:
        value = frame.stack.pop()
        cell = frame.locals[arg] if arg < len(frame.locals) else None
        if not isinstance(cell, list) or len(cell) != 1:
            raise JockyRuntimeError(f"local slot {arg} is not a capture cell")
        cell[0] = value

    def _op_push_cell(self, frame: Frame, arg: Any) -> None:
        """Push the capture cell itself (shared with the new closure)."""
        cell = frame.locals[arg] if arg < len(frame.locals) else None
        if not isinstance(cell, list) or len(cell) != 1:
            raise JockyRuntimeError(f"local slot {arg} is not a capture cell")
        frame.stack.append(cell)

    def _op_dup(self, frame: Frame, arg: Any) -> None:
        if not frame.stack:
            raise JockyRuntimeError("stack underflow")
        frame.stack.append(frame.stack[-1])

    def _op_neg(self, frame: Frame, arg: Any) -> None:
        value = frame.stack.pop()
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise JockyRuntimeError(f"unary '-' needs a number, got {type(value).__name__}")
        frame.stack.append(-value)

    def _op_not(self, frame: Frame, arg: Any) -> None:
        frame.stack.append(not truthy(frame.stack.pop()))

    def _op_jmp(self, frame: Frame, target: int) -> None:
        frame.ip = target

    def _op_jmpf(self, frame: Frame, target: int) -> None:
        if not truthy(frame.stack.pop()):
            frame.ip = target

    def _op_jmpt(self, frame: Frame, target: int) -> None:
        if truthy(frame.stack.pop()):
            frame.ip = target

    def _op_mk_list(self, frame: Frame, count: int) -> None:
        if count:
            items = frame.stack[-count:]
            del frame.stack[-count:]
            frame.stack.append(list(items))
        else:
            frame.stack.append([])

    def _op_mk_map(self, frame: Frame, count: int) -> None:
        if count:
            items = frame.stack[-2 * count:]
            del frame.stack[-2 * count:]
            mapping: Dict[str, Any] = {}
            for i in range(0, len(items), 2):
                mapping[to_str(items[i])] = items[i + 1]
            frame.stack.append(mapping)
        else:
            frame.stack.append({})

    def _op_get_idx(self, frame: Frame, arg: Any) -> None:
        index = frame.stack.pop()
        obj = frame.stack.pop()
        if isinstance(obj, (list, str)):
            if not isinstance(index, int) or isinstance(index, bool):
                raise JockyRuntimeError("list/string index must be an integer")
            try:
                frame.stack.append(obj[index])
            except IndexError:
                raise JockyRuntimeError(f"index {index} out of range (length {len(obj)})")
            return
        if isinstance(obj, dict):
            frame.stack.append(obj.get(to_str(index)))
            return
        raise JockyRuntimeError(f"cannot index {type(obj).__name__}")

    def _op_set_idx(self, frame: Frame, arg: Any) -> None:
        value = frame.stack.pop()
        index = frame.stack.pop()
        obj = frame.stack.pop()
        if isinstance(obj, list):
            if not isinstance(index, int) or isinstance(index, bool):
                raise JockyRuntimeError("list index must be an integer")
            if index < 0:
                index += len(obj)
            if not 0 <= index < len(obj):
                raise JockyRuntimeError(f"index {index} out of range (length {len(obj)})")
            obj[index] = value
            return
        if isinstance(obj, dict):
            obj[to_str(index)] = value
            return
        raise JockyRuntimeError(f"cannot assign into {type(obj).__name__}")

    def _op_get_mem(self, frame: Frame, arg: Any) -> None:
        obj = frame.stack.pop()
        name = self.program.names[arg]
        frame.stack.append(self.member(obj, name))

    def _op_set_mem(self, frame: Frame, arg: Any) -> None:
        value = frame.stack.pop()
        obj = frame.stack.pop()
        name = self.program.names[arg]
        if isinstance(obj, dict):
            obj[name] = value
            return
        raise JockyRuntimeError(f"cannot set member {name!r} on {type(obj).__name__}")

    def _op_mk_fn(self, frame: Frame, proto_idx: int) -> None:
        proto = self.program.protos[proto_idx]
        count = proto.ncaptures
        captures = frame.stack[-count:] if count else []
        if count:
            del frame.stack[-count:]
        frame.stack.append(JFn(proto=proto, captures=list(captures)))

    def _op_call(self, frame: Frame, argc: int) -> None:
        args = frame.stack[-argc:] if argc else []
        if argc:
            del frame.stack[-argc:]
        callee = frame.stack.pop()
        if isinstance(callee, NativeFn):
            self.native_calls += 1
            if len(args) < callee.min_args:
                raise JockyRuntimeError(
                    f"{callee.name}() expects at least {callee.min_args} argument(s), got {len(args)}"
                )
            if callee.max_args is not None and len(args) > callee.max_args:
                raise JockyRuntimeError(
                    f"{callee.name}() expects at most {callee.max_args} argument(s), got {len(args)}"
                )
            frame.stack.append(callee(self, args))
            # A native can run for a long time (a filesystem scan, a socket
            # correlation). The interpreter only samples the deadline between
            # instructions, so one long call used to overrun the budget silently
            # and still report `truncated: false`. Checking here makes that
            # overrun honest.
            self._check_deadline()
            return
        if isinstance(callee, JFn):
            proto = callee.proto
            expected = len(proto.params)
            if len(args) != expected:
                raise JockyRuntimeError(
                    f"{callee.name}() expects {expected} argument(s), got {len(args)}"
                )
            if len(self.frames) >= self.max_frames:
                raise JockyLimitError(f"call depth exceeded ({self.max_frames} frames)")
            self.frames.append(self._new_frame(proto, list(callee.captures) + list(args)))
            return
        raise JockyRuntimeError(f"{type(callee).__name__} is not callable")

    def _op_ret(self, frame: Frame, arg: Any) -> None:
        value = frame.stack.pop() if frame.stack else None
        self._pop_frame(value)

    def _op_iter_init(self, frame: Frame, arg: Any) -> None:
        value = frame.stack.pop()
        if isinstance(value, list):
            items = value
        elif isinstance(value, str):
            items = list(value)
        elif isinstance(value, dict):
            items = [[k, v] for k, v in value.items()]
        elif value is None:
            items = []
        else:
            raise JockyRuntimeError(f"cannot iterate over {type(value).__name__}")
        frame.stack.append(JIter(items))

    def _op_iter_next(self, frame: Frame, target: int) -> None:
        if not frame.stack:
            raise JockyRuntimeError("iterator lost")
        it = frame.stack[-1]
        if not isinstance(it, JIter):
            raise JockyRuntimeError("expected an iterator")
        if it.index >= len(it.items):
            frame.stack.pop()
            frame.ip = target
            return
        frame.stack.append(it.items[it.index])
        it.index += 1

    def _op_emit(self, frame: Frame, arg: Any) -> None:
        self.findings.append(frame.stack.pop())

    def _op_halt(self, frame: Frame, arg: Any) -> None:
        self.frames.clear()

    def _op_try_enter(self, frame: Frame, arg: Any) -> None:
        start_ip, end_ip, handler_ip, slot = arg
        frame.handlers.append((len(frame.stack), start_ip, end_ip, handler_ip, slot))

    def _op_try_exit(self, frame: Frame, arg: Any) -> None:
        if frame.handlers:
            frame.handlers.pop()

    # ------------------------------------------------------ member / methods
    def member(self, obj: Any, name: str) -> Any:
        """Resolve ``obj.name`` — data first for maps, then built-in methods."""
        if isinstance(obj, dict):
            if name in obj:
                return obj[name]
            return self._dict_method(obj, name)
        if isinstance(obj, str):
            return self._str_method(obj, name)
        if isinstance(obj, list):
            return self._list_method(obj, name)
        if isinstance(obj, (int, float)) and not isinstance(obj, bool):
            return self._number_method(obj, name)
        if obj is None:
            return None
        raise JockyRuntimeError(f"cannot read member {name!r} of {type(obj).__name__}")

    def _str_method(self, s: str, name: str) -> Any:
        # name -> (implementation, min arity, max arity)
        table: Dict[str, Tuple[Callable[..., Any], int, Optional[int]]] = {
            "len": (lambda: len(s), 0, 0),
            "upper": (lambda: s.upper(), 0, 0),
            "lower": (lambda: s.lower(), 0, 0),
            "strip": (lambda: s.strip(), 0, 0),
            "split": (lambda sep=None: s.split(sep) if sep is not None else s.split(), 0, 1),
            "replace": (lambda a, b: s.replace(to_str(a), to_str(b)), 2, 2),
            "contains": (lambda sub: to_str(sub) in s, 1, 1),
            "starts_with": (lambda pre: s.startswith(to_str(pre)), 1, 1),
            "ends_with": (lambda suf: s.endswith(to_str(suf)), 1, 1),
            "find": (lambda sub: s.find(to_str(sub)), 1, 1),
            "substr": (lambda start, end=None: s[start:end], 1, 2),
            "to_int": (lambda: int(s.strip() or "0"), 0, 0),
            "to_float": (lambda: _safe_float(s), 0, 0),
            "chars": (lambda: list(s), 0, 0),
            "bytes": (lambda: list(s.encode("utf-8", "surrogateescape")), 0, 0),
            "lines": (lambda: s.splitlines(), 0, 0),
        }
        if name in table:
            fn, lo, hi = table[name]
            return NativeFn(f"str.{name}", lambda vm, args: fn(*args), lo, hi)
        raise JockyRuntimeError(f"string has no member {name!r}")

    def _list_method(self, items: list, name: str) -> Any:
        table: Dict[str, Callable[..., Any]] = {
            "len": lambda: len(items),
            "first": lambda: items[0] if items else None,
            "last": lambda: items[-1] if items else None,
            "push": lambda v: (items.append(v), items)[1],
            "contains": lambda v: any(x == v for x in items),
            "index": lambda v: items.index(v) if v in items else -1,
            "count": lambda v: sum(1 for x in items if x == v),
            "join": lambda sep="": to_str(sep).join(to_str(x) for x in items),
            "slice": lambda start=0, end=None: items[start:end],
            # sort/reverse return new lists, matching the global sort() helper:
            # a collector's result should not be reordered by asking for an
            # ordered view of it. push() and index assignment remain the
            # explicit mutators.
            "reverse": lambda: list(reversed(items)),
            "sort": lambda: sorted(items, key=_sort_key),
            "sum": lambda: sum(x for x in items if isinstance(x, (int, float))),
            "min": lambda: min(items) if items else None,
            "max": lambda: max(items) if items else None,
            "unique": lambda: list(dict.fromkeys(to_str(x) for x in items)),
        }
        if name in table:
            fn = table[name]
            return NativeFn(f"list.{name}", lambda vm, args: fn(*args), 0, None)
        raise JockyRuntimeError(f"list has no member {name!r}")

    def _dict_method(self, mapping: dict, name: str) -> Any:
        table: Dict[str, Callable[..., Any]] = {
            "keys": lambda: list(mapping.keys()),
            "values": lambda: list(mapping.values()),
            "items": lambda: [[k, v] for k, v in mapping.items()],
            "len": lambda: len(mapping),
            "has": lambda k: to_str(k) in mapping,
            "get": lambda k, default=None: mapping.get(to_str(k), default),
            "set": lambda k, v: (mapping.__setitem__(to_str(k), v), mapping)[1],
            "del": lambda k: (mapping.pop(to_str(k), None), mapping)[1],
            "merge": lambda other: {**mapping, **(other if isinstance(other, dict) else {})},
        }
        if name in table:
            fn = table[name]
            return NativeFn(f"map.{name}", lambda vm, args: fn(*args), 0, None)
        raise JockyRuntimeError(f"map has no member {name!r}")

    def _number_method(self, value: Any, name: str) -> Any:
        table: Dict[str, Callable[..., Any]] = {
            "to_str": lambda: to_str(value),
            "to_int": lambda: int(value),
            "to_float": lambda: float(value),
            "abs": lambda: abs(value),
            "hex": lambda: hex(int(value)),
        }
        if name in table:
            return NativeFn(f"num.{name}", lambda vm, args: table[name](), 0, 0)
        raise JockyRuntimeError(f"number has no member {name!r}")


def _safe_float(text: str) -> float:
    """Permissive float parsing, matching the global ``float()`` helper."""
    try:
        return float(text.strip() or "0")
    except ValueError:
        return 0.0


def _sort_key(value: Any) -> Tuple[int, Any]:
    if isinstance(value, bool):
        return (1, int(value))
    if isinstance(value, (int, float)):
        return (0, value)
    return (2, to_str(value))
