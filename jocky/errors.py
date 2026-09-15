"""JOCKY error types."""


class JockyError(Exception):
    """Base class for every JOCKY failure."""


class JockySyntaxError(JockyError):
    """Lexer/parser error carrying a source position."""

    def __init__(self, message: str, line: int = 0, col: int = 0, source: str = ""):
        self.message = message
        self.line = line
        self.col = col
        self.source = source
        super().__init__(self.render())

    def render(self) -> str:
        if not self.line:
            return self.message
        return f"{self.message} (line {self.line}, col {self.col})"


class JockyCompileError(JockyError):
    """Compiler error (unknown name, bad jump target, ...)."""


class JockyRuntimeError(JockyError):
    """Runtime error raised by the VM; catchable from scripts via try/catch."""


class JockyArtifactError(JockyError):
    """Artifact is malformed, truncated or fails its integrity check."""
