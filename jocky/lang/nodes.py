"""
JOCKY AST node definitions.

Every node carries the source position (line/col) so that compiler and
runtime errors can point back at the script.  Nodes are plain dataclasses —
the compiler pattern-matches on the concrete class.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple


@dataclass
class Node:
    line: int = 0
    col: int = 0


# --------------------------------------------------------------------- program
@dataclass
class Program(Node):
    stmts: List[Node] = field(default_factory=list)


@dataclass
class Block(Node):
    stmts: List[Node] = field(default_factory=list)


# ------------------------------------------------------------------ statements
@dataclass
class Let(Node):
    name: str = ""
    expr: Node = None


@dataclass
class Assign(Node):
    target: Node = None      # Ident | Member | Index
    expr: Node = None


@dataclass
class If(Node):
    branches: List[Tuple[Node, Block]] = field(default_factory=list)
    orelse: Optional[Block] = None


@dataclass
class While(Node):
    cond: Node = None
    body: Block = None


@dataclass
class For(Node):
    name: str = ""
    iterable: Node = None
    body: Block = None


@dataclass
class FnDecl(Node):
    name: str = ""
    params: List[str] = field(default_factory=list)
    body: Block = None


@dataclass
class Return(Node):
    expr: Optional[Node] = None


@dataclass
class Break(Node):
    pass


@dataclass
class Continue(Node):
    pass


@dataclass
class Emit(Node):
    expr: Node = None


@dataclass
class ExprStmt(Node):
    expr: Node = None


@dataclass
class TryCatch(Node):
    body: Block = None
    name: str = ""
    handler: Block = None


# ----------------------------------------------------------------- expressions
@dataclass
class IntLit(Node):
    value: int = 0


@dataclass
class FloatLit(Node):
    value: float = 0.0


@dataclass
class StrLit(Node):
    value: str = ""


@dataclass
class Interp(Node):
    """String interpolation: parts are ("t", text) or ("e", node)."""
    parts: List[Tuple[str, Any]] = field(default_factory=list)


@dataclass
class BoolLit(Node):
    value: bool = False


@dataclass
class NilLit(Node):
    pass


@dataclass
class Ident(Node):
    name: str = ""


@dataclass
class ListLit(Node):
    items: List[Node] = field(default_factory=list)


@dataclass
class MapLit(Node):
    """Map literal: pairs of (key expression, value expression)."""
    pairs: List[Tuple[Node, Node]] = field(default_factory=list)


@dataclass
class Unary(Node):
    op: str = ""
    expr: Node = None


@dataclass
class Binary(Node):
    op: str = ""
    left: Node = None
    right: Node = None


@dataclass
class Logical(Node):
    op: str = ""            # "and" | "or"
    left: Node = None
    right: Node = None


@dataclass
class Call(Node):
    callee: Node = None
    args: List[Node] = field(default_factory=list)


@dataclass
class Member(Node):
    obj: Node = None
    name: str = ""


@dataclass
class Index(Node):
    obj: Node = None
    index: Node = None


@dataclass
class Lambda(Node):
    params: List[str] = field(default_factory=list)
    body: Block = None
