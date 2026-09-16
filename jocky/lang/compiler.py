"""
JOCKY bytecode compiler.

The compiler lowers the AST to a flat, stack-machine instruction stream.

Instruction set (canonical names — the polymorphic encoder later renames
them per build)::

    CONST idx           push constants[idx]
    LOADL slot          push frame local
    STOREL slot         pop -> frame local
    LOADG idx           push global by name-table index
    STOREG idx          pop -> global
    POP, DUP            stack shuffling
    ADD SUB MUL DIV MOD arithmetic (also string concat / list concat)
    EQ NE LT LE GT GE IN comparisons
    NEG NOT             unary
    JMP t / JMPF t / JMPT t   control flow (JMPF/JMPT pop)
    JMPI                pop a computed target and jump to it (encoder only --
                        the compiler never emits an indirect jump)
    CALL argc           call callee with argc arguments
    RET                 return from function (implicit nil)
    MK_LIST n           build a list from n stack values
    GET_IDX / SET_IDX   index read/write
    GET_MEM idx / SET_MEM idx   member read/write by name index
    MK_FN proto         push a closure
    ITER_INIT           pop iterable, push iterator
    ITER_NEXT t         push next value, or jump to t when exhausted
    EMIT                pop a finding and record it
    NOP0..NOP7          semantically empty (polymorphic padding)
    HALT                stop the program
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Optional, Tuple

from jocky.errors import JockyCompileError
from jocky.lang import nodes as N


def _walk(node: Any):
    """Yield every AST node reachable from ``node`` (depth first)."""
    if not isinstance(node, N.Node):
        return
    yield node
    for f in fields(node):
        value = getattr(node, f.name)
        if isinstance(value, N.Node):
            yield from _walk(value)
        elif isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, N.Node):
                    yield from _walk(item)
                elif isinstance(item, (list, tuple)):
                    for sub in item:
                        if isinstance(sub, N.Node):
                            yield from _walk(sub)


def _collect_used(node: N.Node) -> set:
    """Names referenced anywhere in the subtree."""
    return {n.name for n in _walk(node) if isinstance(n, N.Ident)}


def _collect_bound(node: N.Node) -> set:
    """Names bound anywhere in the subtree (params, let, for, fn, catch)."""
    bound: set = set()
    for n in _walk(node):
        if isinstance(n, (N.Let, N.For)):
            bound.add(n.name)
        elif isinstance(n, N.FnDecl):
            bound.add(n.name)
            bound.update(n.params)
        elif isinstance(n, N.Lambda):
            bound.update(n.params)
        elif isinstance(n, N.TryCatch):
            bound.add(n.name)
    return bound


# Instruction names grouped for the polymorpher and the disassembler.
NOOP_OPS = tuple(f"NOP{i}" for i in range(8))

# ``JMPI`` is appended rather than slotted in with the other jumps, even though
# that is where it belongs conceptually: a wire image numbers opcodes by
# position in this tuple, so a name in the middle renumbers every opcode after
# it and an image written by an earlier build would decode into *different*
# instructions instead of failing.  Artifacts do not care -- their per-build
# opcode map is keyed by name -- but the inner serialisation does, and the
# project's rule is that a layout change is what moves ``WIRE_VERSION``.
OPCODES = (
    "CONST", "LOADL", "STOREL", "LOAD_CELL", "STORE_CELL", "PUSH_CELL", "LOADG", "STOREG", "POP", "DUP",
    "ADD", "SUB", "MUL", "DIV", "MOD",
    "EQ", "NE", "LT", "LE", "GT", "GE", "IN",
    "NEG", "NOT",
    "JMP", "JMPF", "JMPT",
    "CALL", "RET",
    "MK_LIST", "MK_MAP", "GET_IDX", "SET_IDX", "GET_MEM", "SET_MEM",
    "MK_FN", "ITER_INIT", "ITER_NEXT", "EMIT", "HALT",
    "TRY_ENTER", "TRY_EXIT",
) + NOOP_OPS + ("JMPI",)

_ARITH = {"+": "ADD", "-": "SUB", "*": "MUL", "/": "DIV", "%": "MOD"}
_COMPARE = {"==": "EQ", "!=": "NE", "<": "LT", "<=": "LE", ">": "GT", ">=": "GE", "in": "IN"}


@dataclass
class Proto:
    """A compiled code unit: the main script or one function body."""
    name: str = "<main>"
    params: List[str] = field(default_factory=list)
    captures: List[str] = field(default_factory=list)
    ncaptures: int = 0
    nlocals: int = 0
    cell_slots: List[int] = field(default_factory=list)  # locals stored as shared cells
    code: List[Tuple[str, Any]] = field(default_factory=list)
    handlers: List[Tuple[int, int, int, int]] = field(default_factory=list)
    starts: List[int] = field(default_factory=list)   # instruction indices that begin a statement

    def disassemble(self) -> List[str]:
        out = []
        for ip, (op, arg) in enumerate(self.code):
            out.append(f"{ip:4d}  {op:<10} {'' if arg is None else arg}")
        return out


@dataclass
class Program:
    """A compiled JOCKY program: shared const/name pools plus protos."""
    main: Proto = field(default_factory=Proto)
    protos: List[Proto] = field(default_factory=list)   # function bodies
    consts: List[Any] = field(default_factory=list)
    names: List[str] = field(default_factory=list)

    def all_protos(self) -> List[Proto]:
        return [self.main] + self.protos

    def disassemble(self) -> str:
        lines = ["=== constants ==="]
        for i, c in enumerate(self.consts):
            lines.append(f"[{i}] {c!r}")
        lines.append("=== names ===")
        for i, n in enumerate(self.names):
            lines.append(f"[{i}] {n}")
        for proto in self.all_protos():
            lines.append(f"=== {proto.name} (locals={proto.nlocals}) ===")
            lines.extend(proto.disassemble())
            if proto.handlers:
                lines.append(f"handlers: {proto.handlers}")
        return "\n".join(lines)


class _FunctionScope:
    """Local variable slots for one function body."""

    def __init__(self, params: List[str]):
        self.slots: Dict[str, int] = {}
        self.count = 0
        for p in params:
            self.declare(p)

    def declare(self, name: str) -> int:
        if name not in self.slots:
            self.slots[name] = self.count
            self.count += 1
        return self.slots[name]

    def lookup(self, name: str) -> Optional[int]:
        return self.slots.get(name)


class Compiler:
    """AST -> Program."""

    def __init__(self):
        self.consts: List[Any] = []
        self.names: List[str] = []
        self.protos: List[Proto] = []
        self._const_index: Dict[Any, int] = {}
        self._name_index: Dict[str, int] = {}

        self.proto: Optional[Proto] = None
        self.scope: Optional[_FunctionScope] = None
        # (continue_target, break_jumps_placeholder, iterator_on_stack).
        # The third flag is what makes ``break`` correct inside a ``for``: the
        # loop's iterator lives on the operand stack and ITER_NEXT pops it on
        # normal exhaustion, so leaving by ``break`` must pop it too or the
        # *enclosing* loop's ITER_NEXT finds the wrong iterator and replays the
        # inner sequence forever.
        self._loops: List[Tuple[int, int, bool]] = []
        self._break_patches: List[List[int]] = []
        self._cell_slots: set = set()                # current function's cell-allocated slots

    # ----------------------------------------------------------- local access
    def local_get(self, slot: int) -> None:
        self.emit("LOAD_CELL" if slot in self._cell_slots else "LOADL", slot)

    def local_set(self, slot: int) -> None:
        self.emit("STORE_CELL" if slot in self._cell_slots else "STOREL", slot)

    def _mark_cell(self, slot: int) -> None:
        """Promote a local to a shared cell because a nested fn captures it."""
        if slot in self._cell_slots:
            return
        self._cell_slots.add(slot)
        code = self.proto.code
        for i, (op, arg) in enumerate(code):
            if arg == slot and op in ("LOADL", "STOREL"):
                code[i] = ("LOAD_CELL" if op == "LOADL" else "STORE_CELL", arg)

    # ------------------------------------------------------------- utilities
    def const(self, value: Any) -> int:
        # Python considers 1 == 1.0 == True, so an untagged key would collapse
        # distinct literals into one pool entry: a script writing `0` could
        # emit `false`, and a float could surface as an int in evidence.  The
        # key therefore carries the value's type name.
        try:
            key: Any = (type(value).__name__, value)
            if key in self._const_index:
                return self._const_index[key]
        except TypeError:
            key = ("repr", repr(value))
            if key in self._const_index:
                return self._const_index[key]
        idx = len(self.consts)
        self.consts.append(value)
        self._const_index[key] = idx
        return idx

    def name_idx(self, name: str) -> int:
        if name in self._name_index:
            return self._name_index[name]
        idx = len(self.names)
        self.names.append(name)
        self._name_index[name] = idx
        return idx

    def emit(self, op: str, arg: Any = None) -> int:
        self.proto.code.append((op, arg))
        return len(self.proto.code) - 1

    def patch(self, ip: int, target: int) -> None:
        op, _ = self.proto.code[ip]
        self.proto.code[ip] = (op, target)

    # ----------------------------------------------------------------- entry
    def compile(self, program: N.Program) -> Program:
        main = Proto(name="<main>")
        self.proto = main
        self.scope = _FunctionScope([])
        for stmt in program.stmts:
            self.stmt(stmt)
        self.emit("HALT")
        main.nlocals = self.scope.count
        main.cell_slots = sorted(self._cell_slots)
        return Program(main=main, protos=self.protos, consts=self.consts, names=self.names)

    # ------------------------------------------------------------ statements
    def stmt(self, node: N.Node) -> None:
        self.proto.starts.append(len(self.proto.code))
        if isinstance(node, N.Let):
            self.expr(node.expr)
            slot = self.scope.declare(node.name)
            self.local_set(slot)
        elif isinstance(node, N.Assign):
            self.assign(node)
        elif isinstance(node, N.If):
            self.if_stmt(node)
        elif isinstance(node, N.While):
            self.while_stmt(node)
        elif isinstance(node, N.For):
            self.for_stmt(node)
        elif isinstance(node, N.FnDecl):
            self.fn_decl(node)
        elif isinstance(node, N.Return):
            if node.expr is not None:
                self.expr(node.expr)
            else:
                self.emit("CONST", self.const(None))
            self.emit("RET")
        elif isinstance(node, N.Break):
            if not self._loops:
                raise JockyCompileError(f"'break' outside of a loop (line {node.line})")
            if self._loops[-1][2]:
                # A ``for`` leaves its iterator on the operand stack (ITER_NEXT
                # pops it when the loop ends by exhaustion). Leaving by ``break``
                # must pop it too, or the enclosing loop's ITER_NEXT sees the
                # inner iterator and replays the inner sequence forever — the
                # outer variable is rebound to the inner values and the loop
                # never terminates.
                self.emit("POP")
            self._break_patches[-1].append(self.emit("JMP", -1))
        elif isinstance(node, N.Continue):
            if not self._loops:
                raise JockyCompileError(f"'continue' outside of a loop (line {node.line})")
            self.emit("JMP", self._loops[-1][0])
        elif isinstance(node, N.Emit):
            self.expr(node.expr)
            self.emit("EMIT")
        elif isinstance(node, N.TryCatch):
            self.try_stmt(node)
        elif isinstance(node, N.ExprStmt):
            self.expr(node.expr)
            self.emit("POP")
        elif isinstance(node, N.Block):
            for s in node.stmts:
                self.stmt(s)
        else:  # pragma: no cover - defensive
            raise JockyCompileError(f"unsupported statement {type(node).__name__}")

    def assign(self, node: N.Assign) -> None:
        target = node.target
        if isinstance(target, N.Ident):
            self.expr(node.expr)
            slot = self.scope.lookup(target.name)
            if slot is not None:
                self.local_set(slot)
            else:
                self.emit("STOREG", self.name_idx(target.name))
            return
        if isinstance(target, N.Member):
            self.expr(target.obj)
            self.expr(node.expr)
            self.emit("SET_MEM", self.name_idx(target.name))
            return
        if isinstance(target, N.Index):
            self.expr(target.obj)
            self.expr(target.index)
            self.expr(node.expr)
            self.emit("SET_IDX")
            return
        raise JockyCompileError(f"invalid assignment target (line {node.line})")

    def if_stmt(self, node: N.If) -> None:
        end_jumps: List[int] = []
        for cond, block in node.branches:
            self.expr(cond)
            jf = self.emit("JMPF", -1)
            for s in block.stmts:
                self.stmt(s)
            end_jumps.append(self.emit("JMP", -1))
            self.patch(jf, len(self.proto.code))
        if node.orelse is not None:
            for s in node.orelse.stmts:
                self.stmt(s)
        for j in end_jumps:
            self.patch(j, len(self.proto.code))

    def while_stmt(self, node: N.While) -> None:
        start = len(self.proto.code)
        self.expr(node.cond)
        jf = self.emit("JMPF", -1)
        self._loops.append((start, 0, False))   # a ``while`` keeps nothing on the stack
        self._break_patches.append([])
        for s in node.body.stmts:
            self.stmt(s)
        self.emit("JMP", start)
        self.patch(jf, len(self.proto.code))
        for patch_ip in self._break_patches.pop():
            self.patch(patch_ip, len(self.proto.code))
        self._loops.pop()

    def for_stmt(self, node: N.For) -> None:
        self.expr(node.iterable)
        self.emit("ITER_INIT")
        start = len(self.proto.code)
        jn = self.emit("ITER_NEXT", -1)
        slot = self.scope.declare(node.name)
        self.local_set(slot)
        self._loops.append((start, 0, True))    # ITER_INIT left an iterator on the stack
        self._break_patches.append([])
        for s in node.body.stmts:
            self.stmt(s)
        self.emit("JMP", start)
        self.patch(jn, len(self.proto.code))
        for patch_ip in self._break_patches.pop():
            self.patch(patch_ip, len(self.proto.code))
        self._loops.pop()

    def fn_decl(self, node: N.FnDecl) -> None:
        proto = self.compile_function(node.name, node.params, node.body)
        idx = len(self.protos)
        self.protos.append(proto)
        self.emit("MK_FN", idx)
        # top-level functions live in globals; nested ones shadow as locals
        slot = self.scope.lookup(node.name)
        if slot is not None:
            self.local_set(slot)
        else:
            self.emit("STOREG", self.name_idx(node.name))

    def _captures_for(self, params: List[str], body: N.Block) -> List[str]:
        """Free names of a nested function that resolve in the enclosing scope."""
        used = _collect_used(body)
        bound = _collect_bound(body) | set(params)
        return sorted(n for n in (used - bound) if self.scope.lookup(n) is not None)

    def compile_function(self, name: str, params: List[str], body: N.Block) -> Proto:
        captures = self._captures_for(params, body)
        capture_slots = []
        for cap in captures:
            slot = self.scope.lookup(cap)
            capture_slots.append(slot)
            self._mark_cell(slot)                # enclosing local becomes a shared cell
        for slot in capture_slots:               # parent pushes the cells themselves
            self.emit("PUSH_CELL", slot)
        saved_proto, saved_scope, saved_loops, saved_patches, saved_cells = (
            self.proto, self.scope, self._loops, self._break_patches, self._cell_slots,
        )
        proto = Proto(name=name or "<lambda>", params=list(params),
                      captures=captures, ncaptures=len(captures))
        self.proto = proto
        self.scope = _FunctionScope(list(captures) + list(params))
        self._cell_slots = set(range(len(captures)))   # captures arrive as cells
        self._loops = []
        self._break_patches = []
        for stmt in body.stmts:
            self.stmt(stmt)
        self.emit("CONST", self.const(None))
        self.emit("RET")
        proto.nlocals = self.scope.count
        proto.cell_slots = sorted(self._cell_slots)
        self.proto, self.scope, self._loops, self._break_patches, self._cell_slots = (
            saved_proto, saved_scope, saved_loops, saved_patches, saved_cells,
        )
        return proto

    def try_stmt(self, node: N.TryCatch) -> None:
        enter = self.emit("TRY_ENTER", [-1, -1, -1])
        start = enter + 1
        for s in node.body.stmts:
            self.stmt(s)
        self.emit("TRY_EXIT")
        skip = self.emit("JMP", -1)
        handler_ip = len(self.proto.code)
        slot = self.scope.declare(node.name)
        self.local_set(slot)
        for s in node.handler.stmts:
            self.stmt(s)
        self.patch(skip, len(self.proto.code))
        end_ip = handler_ip          # protected region ends where the handler begins
        # TRY_ENTER arg: (start_ip, end_ip, handler_ip, slot) — start patched here too
        self.proto.code[enter] = ("TRY_ENTER", (start, end_ip, handler_ip, slot))
        self.proto.handlers.append((start, end_ip, handler_ip, slot))

    # ----------------------------------------------------------- expressions
    def expr(self, node: N.Node) -> None:
        if isinstance(node, N.IntLit) or isinstance(node, N.FloatLit):
            self.emit("CONST", self.const(node.value))
        elif isinstance(node, N.StrLit):
            self.emit("CONST", self.const(node.value))
        elif isinstance(node, N.BoolLit):
            self.emit("CONST", self.const(node.value))
        elif isinstance(node, N.NilLit):
            self.emit("CONST", self.const(None))
        elif isinstance(node, N.Ident):
            slot = self.scope.lookup(node.name)
            if slot is not None:
                self.local_get(slot)
            else:
                self.emit("LOADG", self.name_idx(node.name))
        elif isinstance(node, N.Interp):
            parts = list(node.parts)
            if not parts or parts[0][0] == "e":
                # Start from an empty literal so the concatenation below yields a
                # *string*: "{x}" must be text, not the raw value of x.
                parts.insert(0, ("t", ""))
            first = True
            for kind, part in parts:
                if kind == "t":
                    self.emit("CONST", self.const(part))
                else:
                    self.expr(part)
                if not first:
                    self.emit("ADD")
                first = False
        elif isinstance(node, N.ListLit):
            for item in node.items:
                self.expr(item)
            self.emit("MK_LIST", len(node.items))
        elif isinstance(node, N.MapLit):
            for key, value in node.pairs:
                self.expr(key)
                self.expr(value)
            self.emit("MK_MAP", len(node.pairs))
        elif isinstance(node, N.Unary):
            self.expr(node.expr)
            self.emit("NOT" if node.op == "not" else "NEG")
        elif isinstance(node, N.Binary):
            self.expr(node.left)
            self.expr(node.right)
            self.emit(_ARITH.get(node.op) or _COMPARE[node.op])
        elif isinstance(node, N.Logical):
            self.expr(node.left)
            self.emit("DUP")
            guard = self.emit("JMPF" if node.op == "and" else "JMPT", -1)
            self.emit("POP")
            self.expr(node.right)
            self.patch(guard, len(self.proto.code))
        elif isinstance(node, N.Call):
            self.expr(node.callee)
            for arg in node.args:
                self.expr(arg)
            self.emit("CALL", len(node.args))
        elif isinstance(node, N.Member):
            self.expr(node.obj)
            self.emit("GET_MEM", self.name_idx(node.name))
        elif isinstance(node, N.Index):
            self.expr(node.obj)
            self.expr(node.index)
            self.emit("GET_IDX")
        elif isinstance(node, N.Lambda):
            proto = self.compile_function("<lambda>", node.params, node.body)
            idx = len(self.protos)
            self.protos.append(proto)
            self.emit("MK_FN", idx)
        else:  # pragma: no cover - defensive
            raise JockyCompileError(f"unsupported expression {type(node).__name__}")


def compile_program(program: N.Program) -> Program:
    """Compile a parsed AST into a :class:`Program`.

    The compiler walks expressions recursively too, and a *shallow* but very
    long chain (`1.to_str().to_str()…`, 500 links) exhausts the stack here
    rather than in the parser — a deep tree is not needed, only a wide one. The
    failure is reported as a compile error for the same reason the parser
    reports its own limit: no host exception may escape the front end.
    """
    try:
        return Compiler().compile(program)
    except RecursionError:
        raise JockyCompileError(
            "program nests too deeply to compile (expression or statement nesting)") from None
