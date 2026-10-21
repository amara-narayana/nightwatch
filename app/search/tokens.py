"""
NIGHTWATCH — SPL Search Tokens
"""

from enum import Enum, auto
from typing import Any, NamedTuple


class TokenType(Enum):
    # Literals & Identifiers
    IDENTIFIER = auto()
    STRING = auto()
    NUMBER = auto()

    # Operators
    PIPE = auto()         # |
    EQUALS = auto()       # =
    NOT_EQUALS = auto()   # !=
    GT = auto()           # >
    LT = auto()           # <
    GTE = auto()          # >=
    LTE = auto()          # <=
    PLUS = auto()         # +
    MINUS = auto()        # -
    STAR = auto()         # *
    SLASH = auto()        # /

    # Punctuation
    LPAREN = auto()       # (
    RPAREN = auto()       # )
    COMMA = auto()        # ,

    # Boolean & Logical Keywords
    AND = auto()
    OR = auto()
    NOT = auto()
    BY = auto()
    AS = auto()
    OVER = auto()

    # End of Input
    EOF = auto()


class Token(NamedTuple):
    type: TokenType
    value: Any
    pos: int
