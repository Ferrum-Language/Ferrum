#pragma once
#include "ferrum/Token.h"
#include <string>
#include <vector>
#include <unordered_map>

namespace ferrum {

class Lexer {
public:
    explicit Lexer(std::string source, std::string filename = "<input>");

    std::vector<Token> tokenize();

private:
    std::string src;
    std::string filename;
    size_t pos = 0;
    int line = 1;
    int col = 1;

    static const std::unordered_map<std::string, TokenKind> keywords;

    char peek(int offset = 0) const;
    char advance();
    bool match(char expected);
    void skipWhitespaceAndComments();

    Token makeToken(TokenKind kind, const std::string& lex) const;
    Token lexNumber();
    Token lexString();
    Token lexChar();
    Token lexLifetime(int startLine, int startCol);
    Token lexIdent();

    bool isAtEnd() const { return pos >= src.size(); }
    bool isDigit(char c) const { return c >= '0' && c <= '9'; }
    bool isAlpha(char c) const {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
    }
    bool isAlphaNum(char c) const { return isAlpha(c) || isDigit(c); }
};

} // namespace ferrum
