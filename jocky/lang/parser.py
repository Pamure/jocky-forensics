"""
JOCKY parser — token stream to AST (recursive descent, precedence climbing).

Grammar (informal)::

    program    := stmt*
    stmt       := let | set | if | while | for | fn | return | break
                | continue | emit | try | block | expr-stmt
    let        := 'let' IDENT '=' expr
    set        := assignable '=' expr
    if         := 'if' expr block ('elif' expr block)* ('else' block)?
    while      := 'while' expr block
    for        := 'for' IDENT 'in' expr block
    fn         := 'fn' IDENT '(' params ')' block
    try        := 'try' block 'catch' IDENT block
    emit       := 'emit' expr
    block      := '{' stmt* '}'
    expr       := or
    or         := and ('or' and)*
    and        := not ('and' not)*
    not        := 'not' not | comparison
    comparison := additive (('=='|'!='|'<'|'<='|'>'|'>='|'in') additive)*
    additive   := multiplicative (('+'|'-') multiplicative)*
    multiplicative := unary (('*'|'/'|'%') unary)*
    unary      := '-' unary | postfix
    postfix    := primary ( '(' args ')' | '[' expr ']' | '.' IDENT )*
    primary    := INT | FLOAT | STRING | 'true' | 'false' | 'nil' | IDENT
                | '(' expr ')' | list-literal | lambda
"""
from __future__ import annotations

from typing import List, Optional

from jocky.errors import JockySyntaxError
from jocky.lang import nodes as N
from jocky.lang.lexer import Lexer, Token

_COMPARISON_OPS = ("==", "!=", "<", "<=", ">", ">=")


class Parser:
    """Builds an AST from a token list."""

    def __init__(self, tokens: List[Token], source: str = ""):
        self.toks = tokens
        self.i = 0
        self.source = source

    # ------------------------------------------------------------ token access
    def _peek(self, k: int = 0) -> Token:
        j = self.i + k
        return self.toks[j] if j < len(self.toks) else self.toks[-1]

    def _next(self) -> Token:
        tok = self._peek()
        if tok.kind != "eof":
            self.i += 1
        return tok

    def _at_kw(self, *names: str) -> bool:
        tok = self._peek()
        return tok.kind == "kw" and tok.value in names

    def _at_op(self, *ops: str) -> bool:
        tok = self._peek()
        return tok.kind == "op" and tok.value in ops

    def _at(self, kind: str) -> bool:
        return self._peek().kind == kind

    def _accept_kw(self, name: str) -> bool:
        if self._at_kw(name):
            self._next()
            return True
        return False

    def _accept_op(self, op: str) -> bool:
        if self._at_op(op):
            self._next()
            return True
        return False

    def _expect_kw(self, name: str) -> Token:
        if not self._at_kw(name):
            self._fail(f"expected keyword {name!r}")
        return self._next()

    def _expect_op(self, op: str) -> Token:
        if not self._at_op(op):
            self._fail(f"expected {op!r}")
        return self._next()

    def _expect_ident(self) -> Token:
        if not self._at("ident"):
            self._fail("expected identifier")
        return self._next()

    def _fail(self, msg: str, tok: Optional[Token] = None):
        tok = tok or self._peek()
        found = "end of input" if tok.kind == "eof" else f"{tok.kind} {tok.value!r}"
        raise JockySyntaxError(f"{msg} but found {found}", tok.line, tok.col, self.source)

    # ------------------------------------------------------------- statements
    def parse_program(self) -> N.Program:
        stmts: List[N.Node] = []
        first = self._peek()
        while not self._at("eof"):
            stmts.append(self.parse_stmt())
        return N.Program(line=first.line, col=first.col, stmts=stmts)

    def parse_block(self) -> N.Block:
        open_tok = self._expect_op("{")
        stmts: List[N.Node] = []
        while not self._at_op("}"):
            if self._at("eof"):
                self._fail("unterminated block", open_tok)
            stmts.append(self.parse_stmt())
        self._expect_op("}")
        return N.Block(line=open_tok.line, col=open_tok.col, stmts=stmts)

    def parse_stmt(self) -> N.Node:
        tok = self._peek()
        if tok.kind == "kw":
            handler = {
                "let": self._parse_let,
                "set": self._parse_set,
                "if": self._parse_if,
                "while": self._parse_while,
                "for": self._parse_for,
                "fn": self._parse_fn_decl,
                "return": self._parse_return,
                "break": self._parse_break,
                "continue": self._parse_continue,
                "emit": self._parse_emit,
                "try": self._parse_try,
            }.get(tok.value)
            if handler is not None:
                return handler()
        if self._at_op("{"):
            return self.parse_block()
        expr = self.parse_expr()
        return N.ExprStmt(line=expr.line, col=expr.col, expr=expr)

    def _parse_let(self) -> N.Let:
        tok = self._expect_kw("let")
        name = self._expect_ident()
        self._expect_op("=")
        expr = self.parse_expr()
        return N.Let(line=tok.line, col=tok.col, name=name.value, expr=expr)

    def _parse_set(self) -> N.Assign:
        tok = self._expect_kw("set")
        target = self.parse_expr()
        if not isinstance(target, (N.Ident, N.Member, N.Index)):
            self._fail("assignment target must be a name, member or index", tok)
        self._expect_op("=")
        expr = self.parse_expr()
        return N.Assign(line=tok.line, col=tok.col, target=target, expr=expr)

    def _parse_if(self) -> N.If:
        tok = self._expect_kw("if")
        branches = []
        cond = self.parse_expr()
        branches.append((cond, self.parse_block()))
        while self._accept_kw("elif"):
            c = self.parse_expr()
            branches.append((c, self.parse_block()))
        orelse = self.parse_block() if self._accept_kw("else") else None
        return N.If(line=tok.line, col=tok.col, branches=branches, orelse=orelse)

    def _parse_while(self) -> N.While:
        tok = self._expect_kw("while")
        cond = self.parse_expr()
        body = self.parse_block()
        return N.While(line=tok.line, col=tok.col, cond=cond, body=body)

    def _parse_for(self) -> N.For:
        tok = self._expect_kw("for")
        name = self._expect_ident()
        self._expect_kw("in")
        iterable = self.parse_expr()
        body = self.parse_block()
        return N.For(line=tok.line, col=tok.col, name=name.value, iterable=iterable, body=body)

    def _parse_params(self) -> List[str]:
        self._expect_op("(")
        params: List[str] = []
        if not self._at_op(")"):
            while True:
                params.append(self._expect_ident().value)
                if not self._accept_op(","):
                    break
        self._expect_op(")")
        return params

    def _parse_fn_decl(self) -> N.FnDecl:
        tok = self._expect_kw("fn")
        name = self._expect_ident()
        params = self._parse_params()
        body = self.parse_block()
        return N.FnDecl(line=tok.line, col=tok.col, name=name.value, params=params, body=body)

    def _parse_lambda(self) -> N.Lambda:
        tok = self._expect_kw("fn")
        params = self._parse_params()
        body = self.parse_block()
        return N.Lambda(line=tok.line, col=tok.col, params=params, body=body)

    def _parse_return(self) -> N.Return:
        tok = self._expect_kw("return")
        if self._at("eof") or self._at_op("}"):
            return N.Return(line=tok.line, col=tok.col, expr=None)
        expr = self.parse_expr()
        return N.Return(line=tok.line, col=tok.col, expr=expr)

    def _parse_break(self) -> N.Break:
        tok = self._expect_kw("break")
        return N.Break(line=tok.line, col=tok.col)

    def _parse_continue(self) -> N.Continue:
        tok = self._expect_kw("continue")
        return N.Continue(line=tok.line, col=tok.col)

    def _parse_emit(self) -> N.Emit:
        tok = self._expect_kw("emit")
        expr = self.parse_expr()
        return N.Emit(line=tok.line, col=tok.col, expr=expr)

    def _parse_try(self) -> N.TryCatch:
        tok = self._expect_kw("try")
        body = self.parse_block()
        self._expect_kw("catch")
        name = self._expect_ident()
        handler = self.parse_block()
        return N.TryCatch(line=tok.line, col=tok.col, body=body, name=name.value, handler=handler)

    # ------------------------------------------------------------ expressions
    def parse_expr(self) -> N.Node:
        return self._parse_or()

    def _parse_or(self) -> N.Node:
        left = self._parse_and()
        while self._at_kw("or"):
            tok = self._next()
            right = self._parse_and()
            left = N.Logical(line=tok.line, col=tok.col, op="or", left=left, right=right)
        return left

    def _parse_and(self) -> N.Node:
        left = self._parse_not()
        while self._at_kw("and"):
            tok = self._next()
            right = self._parse_not()
            left = N.Logical(line=tok.line, col=tok.col, op="and", left=left, right=right)
        return left

    def _parse_not(self) -> N.Node:
        if self._at_kw("not"):
            tok = self._next()
            operand = self._parse_not()
            return N.Unary(line=tok.line, col=tok.col, op="not", expr=operand)
        return self._parse_comparison()

    def _parse_comparison(self) -> N.Node:
        left = self._parse_additive()
        while True:
            tok = self._peek()
            if tok.kind == "op" and tok.value in _COMPARISON_OPS:
                self._next()
                right = self._parse_additive()
                left = N.Binary(line=tok.line, col=tok.col, op=tok.value, left=left, right=right)
                continue
            if tok.kind == "kw" and tok.value == "in":
                self._next()
                right = self._parse_additive()
                left = N.Binary(line=tok.line, col=tok.col, op="in", left=left, right=right)
                continue
            break
        return left

    def _parse_additive(self) -> N.Node:
        left = self._parse_multiplicative()
        while self._at_op("+", "-"):
            tok = self._next()
            right = self._parse_multiplicative()
            left = N.Binary(line=tok.line, col=tok.col, op=tok.value, left=left, right=right)
        return left

    def _parse_multiplicative(self) -> N.Node:
        left = self._parse_unary()
        while self._at_op("*", "/", "%"):
            tok = self._next()
            right = self._parse_unary()
            left = N.Binary(line=tok.line, col=tok.col, op=tok.value, left=left, right=right)
        return left

    def _parse_unary(self) -> N.Node:
        if self._at_op("-"):
            tok = self._next()
            operand = self._parse_unary()
            return N.Unary(line=tok.line, col=tok.col, op="-", expr=operand)
        return self._parse_postfix()

    def _parse_postfix(self) -> N.Node:
        expr = self._parse_primary()
        while True:
            if self._at_op("("):
                tok = self._next()
                args: List[N.Node] = []
                if not self._at_op(")"):
                    while True:
                        args.append(self.parse_expr())
                        if not self._accept_op(","):
                            break
                self._expect_op(")")
                expr = N.Call(line=tok.line, col=tok.col, callee=expr, args=args)
                continue
            if self._at_op("["):
                tok = self._next()
                index = self.parse_expr()
                self._expect_op("]")
                expr = N.Index(line=tok.line, col=tok.col, obj=expr, index=index)
                continue
            if self._at_op("."):
                tok = self._next()
                name = self._expect_ident()
                expr = N.Member(line=tok.line, col=tok.col, obj=expr, name=name.value)
                continue
            break
        return expr

    def _parse_primary(self) -> N.Node:
        tok = self._peek()
        if tok.kind == "int":
            self._next()
            return N.IntLit(line=tok.line, col=tok.col, value=tok.value)
        if tok.kind == "float":
            self._next()
            return N.FloatLit(line=tok.line, col=tok.col, value=tok.value)
        if tok.kind == "str":
            self._next()
            return self._build_string(tok)
        if tok.kind == "ident":
            self._next()
            return N.Ident(line=tok.line, col=tok.col, name=tok.value)
        if tok.kind == "kw":
            if tok.value == "true":
                self._next()
                return N.BoolLit(line=tok.line, col=tok.col, value=True)
            if tok.value == "false":
                self._next()
                return N.BoolLit(line=tok.line, col=tok.col, value=False)
            if tok.value == "nil":
                self._next()
                return N.NilLit(line=tok.line, col=tok.col)
            if tok.value == "fn":
                return self._parse_lambda()
        if self._at_op("("):
            self._next()
            expr = self.parse_expr()
            self._expect_op(")")
            return expr
        if self._at_op("["):
            self._next()
            items: List[N.Node] = []
            if not self._at_op("]"):
                while True:
                    items.append(self.parse_expr())
                    if not self._accept_op(","):
                        break
            self._expect_op("]")
            return N.ListLit(line=tok.line, col=tok.col, items=items)
        if self._at_op("{"):
            return self._parse_map_literal()
        self._fail("expected an expression")

    def _parse_map_literal(self) -> N.MapLit:
        """``{key: value, ...}`` — bare identifiers are string keys."""
        open_tok = self._expect_op("{")
        pairs: List[tuple] = []
        if not self._at_op("}"):
            while True:
                key_tok = self._peek()
                if key_tok.kind == "ident":
                    self._next()
                    key: N.Node = N.StrLit(line=key_tok.line, col=key_tok.col,
                                           value=key_tok.value)
                elif key_tok.kind == "str":
                    self._next()
                    key = self._build_string(key_tok)
                else:
                    self._fail("map keys must be identifiers or strings")
                self._expect_op(":")
                value = self.parse_expr()
                pairs.append((key, value))
                if not self._accept_op(","):
                    break
        self._expect_op("}")
        return N.MapLit(line=open_tok.line, col=open_tok.col, pairs=pairs)

    def _build_string(self, tok: Token) -> N.Node:
        segments = tok.value
        if len(segments) == 1 and segments[0][0] == "t":
            return N.StrLit(line=tok.line, col=tok.col, value=segments[0][1])
        parts = []
        for seg in segments:
            if seg[0] == "t":
                parts.append(("t", seg[1]))
            else:
                _, code, line, col = seg
                sub = Parser(Lexer(code).tokenize(), code)
                node = sub.parse_expr()
                if not sub._at("eof"):
                    raise JockySyntaxError("trailing input in interpolation", line, col, code)
                parts.append(("e", node))
        return N.Interp(line=tok.line, col=tok.col, parts=parts)


def parse(source: str) -> N.Program:
    """Parse a JOCKY source string into an AST."""
    tokens = Lexer(source).tokenize()
    return Parser(tokens, source).parse_program()
