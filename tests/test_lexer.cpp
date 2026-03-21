#include "ferrum/Lexer.h"
#include <cassert>
#include <iostream>

using namespace ferrum;

void test_basic_tokens() {
    Lexer lex("int x = 42;", "<test>");
    auto tokens = lex.tokenize();
    assert(tokens[0].kind == TokenKind::KW_INT);
    assert(tokens[1].kind == TokenKind::IDENT);
    assert(tokens[1].lexeme == "x");
    assert(tokens[2].kind == TokenKind::EQ);
    assert(tokens[3].kind == TokenKind::INT_LIT);
    assert(std::get<long long>(tokens[3].value) == 42);
    assert(tokens[4].kind == TokenKind::SEMICOLON);
    std::cout << "✓ test_basic_tokens\n";
}

void test_borrow_tokens() {
    Lexer lex("&x &mut y", "<test>");
    auto tokens = lex.tokenize();
    assert(tokens[0].kind == TokenKind::AMP);
    assert(tokens[2].kind == TokenKind::AMP_MUT);
    std::cout << "✓ test_borrow_tokens\n";
}

void test_keywords() {
    Lexer lex("new move unsafe return", "<test>");
    auto tokens = lex.tokenize();
    assert(tokens[0].kind == TokenKind::KW_NEW);
    assert(tokens[1].kind == TokenKind::KW_MOVE);
    assert(tokens[2].kind == TokenKind::KW_UNSAFE);
    assert(tokens[3].kind == TokenKind::KW_RETURN);
    std::cout << "✓ test_keywords\n";
}

int main() {
    std::cout << "=== Ferrum Lexer Tests ===\n";
    test_basic_tokens();
    test_borrow_tokens();
    test_keywords();
    std::cout << "All tests passed!\n";
}
