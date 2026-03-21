#pragma once
#include <string>
#include <variant>

namespace ferrum {

enum class TokenKind {
    // Literals
    INT_LIT, FLOAT_LIT, STRING_LIT, CHAR_LIT,

    // Identifiers & keywords
    IDENT,
    KW_INT, KW_FLOAT, KW_CHAR, KW_VOID, KW_BOOL,
    KW_IF, KW_ELSE, KW_WHILE, KW_FOR, KW_RETURN,
    KW_STRUCT, KW_ENUM, KW_IMPORT, KW_EXTERN,
    KW_NEW, KW_MOVE, KW_UNSAFE, KW_MUT,
    KW_TRUE, KW_FALSE, KW_NULL,

    // Operators
    PLUS, MINUS, STAR, SLASH, PERCENT,
    AMP,        // & (borrow or bitwise and)
    AMP_MUT,    // &mut
    PIPE, CARET, TILDE, BANG,
    EQ, EQ_EQ, BANG_EQ,
    LT, GT, LT_EQ, GT_EQ,
    PLUS_EQ, MINUS_EQ, STAR_EQ, SLASH_EQ,
    AND_AND, PIPE_PIPE,
    ARROW,      // ->
    DOUBLE_COLON, // ::
    DOT, COMMA, COLON, SEMICOLON,

    // Delimiters
    LPAREN, RPAREN,
    LBRACE, RBRACE,
    LBRACKET, RBRACKET,

    // Special
    LIFETIME,   // 'ident  (lifetime annotation, e.g. 'a)
    EOF_TOK, ERROR
};

struct Token {
    TokenKind kind;
    std::string lexeme;
    int line;
    int col;

    // For literals
    std::variant<std::monostate, long long, double, std::string> value;

    Token(TokenKind k, std::string lex, int l, int c)
        : kind(k), lexeme(std::move(lex)), line(l), col(c) {}

    bool is(TokenKind k) const { return kind == k; }
    bool isKeyword() const {
        return kind >= TokenKind::KW_INT && kind <= TokenKind::KW_NULL;
    }
    std::string toString() const;
};

} // namespace ferrum
