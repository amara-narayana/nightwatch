"""
NIGHTWATCH — SPL Lexer / Tokenizer
"""

import re
from typing import List
from app.search.tokens import Token, TokenType


class LexerError(Exception):
    def __init__(self, message: str, pos: int):
        super().__init__(f"{message} at position {pos}")
        self.pos = pos


KEYWORDS = {
    "AND": TokenType.AND,
    "OR": TokenType.OR,
    "NOT": TokenType.NOT,
    "BY": TokenType.BY,
    "AS": TokenType.AS,
    "OVER": TokenType.OVER,
}


class Lexer:
    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.length = len(text)

    def current_char(self) -> str:
        if self.pos >= self.length:
            return ""
        return self.text[self.pos]

    def peek(self, offset: int = 1) -> str:
        target = self.pos + offset
        if target >= self.length:
            return ""
        return self.text[target]

    def advance(self) -> str:
        c = self.current_char()
        self.pos += 1
        return c

    def skip_whitespace(self) -> None:
        while self.pos < self.length and self.current_char().isspace():
            self.advance()

    def tokenize(self) -> List[Token]:
        tokens: List[Token] = []

        while self.pos < self.length:
            self.skip_whitespace()
            if self.pos >= self.length:
                break

            start_pos = self.pos
            c = self.current_char()

            # Pipe
            if c == '|':
                tokens.append(Token(TokenType.PIPE, "|", start_pos))
                self.advance()
            elif c == '(':
                tokens.append(Token(TokenType.LPAREN, "(", start_pos))
                self.advance()
            elif c == ')':
                tokens.append(Token(TokenType.RPAREN, ")", start_pos))
                self.advance()
            elif c == ',':
                tokens.append(Token(TokenType.COMMA, ",", start_pos))
                self.advance()
            elif c == '+':
                tokens.append(Token(TokenType.PLUS, "+", start_pos))
                self.advance()
            elif c == '-':
                # Distinguish negative number from minus sign
                if self.peek().isdigit():
                    num = self._read_number()
                    tokens.append(Token(TokenType.NUMBER, num, start_pos))
                else:
                    tokens.append(Token(TokenType.MINUS, "-", start_pos))
                    self.advance()
            elif c == '*':
                tokens.append(Token(TokenType.STAR, "*", start_pos))
                self.advance()
            elif c == '/':
                tokens.append(Token(TokenType.SLASH, "/", start_pos))
                self.advance()
            elif c == '=':
                tokens.append(Token(TokenType.EQUALS, "=", start_pos))
                self.advance()
            elif c == '!':
                if self.peek() == '=':
                    self.advance()
                    self.advance()
                    tokens.append(Token(TokenType.NOT_EQUALS, "!=", start_pos))
                else:
                    # Treat ! as NOT
                    self.advance()
                    tokens.append(Token(TokenType.NOT, "NOT", start_pos))
            elif c == '>':
                if self.peek() == '=':
                    self.advance()
                    self.advance()
                    tokens.append(Token(TokenType.GTE, ">=", start_pos))
                else:
                    self.advance()
                    tokens.append(Token(TokenType.GT, ">", start_pos))
            elif c == '<':
                if self.peek() == '=':
                    self.advance()
                    self.advance()
                    tokens.append(Token(TokenType.LTE, "<=", start_pos))
                else:
                    self.advance()
                    tokens.append(Token(TokenType.LT, "<", start_pos))
            elif c in ('"', "'"):
                # Quoted string literal
                s = self._read_string(c)
                tokens.append(Token(TokenType.STRING, s, start_pos))
            elif c.isdigit():
                num = self._read_number()
                tokens.append(Token(TokenType.NUMBER, num, start_pos))
            else:
                # Identifier or keyword
                ident = self._read_identifier()
                upper_ident = ident.upper()
                if upper_ident in KEYWORDS:
                    tokens.append(Token(KEYWORDS[upper_ident], upper_ident, start_pos))
                else:
                    tokens.append(Token(TokenType.IDENTIFIER, ident, start_pos))

        tokens.append(Token(TokenType.EOF, "", self.pos))
        return tokens

    def _read_string(self, quote_char: str) -> str:
        self.advance()  # Skip opening quote
        chars = []
        while self.pos < self.length:
            c = self.current_char()
            if c == '\\':
                self.advance()
                if self.pos < self.length:
                    chars.append(self.advance())
            elif c == quote_char:
                self.advance()  # Skip closing quote
                return "".join(chars)
            else:
                chars.append(self.advance())
        return "".join(chars)

    def _read_number(self):
        start = self.pos
        if self.current_char() == '-':
            self.advance()
        while self.pos < self.length and self.current_char().isdigit():
            self.advance()
        if self.pos < self.length and self.current_char() == '.':
            self.advance()
            while self.pos < self.length and self.current_char().isdigit():
                self.advance()
            return float(self.text[start:self.pos])
        return int(self.text[start:self.pos])

    def _read_identifier(self) -> str:
        start = self.pos
        # Valid identifier characters: letters, digits, _, ., :, *, @, %
        while self.pos < self.length:
            c = self.current_char()
            if c.isalnum() or c in ('_', '.', ':', '*', '@', '%', '$', '-'):
                self.advance()
            else:
                break
        return self.text[start:self.pos]
