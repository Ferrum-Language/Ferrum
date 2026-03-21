#include "ferrum/Lexer.h"
#include "ferrum/Parser.h"
#include "ferrum/BorrowChecker.h"
#include <cassert>
#include <iostream>

using namespace ferrum;

Program parse(const std::string& src) {
    Lexer lex(src, "<test>");
    auto tokens = lex.tokenize();
    Parser parser(tokens);
    return parser.parse();
}

void test_valid_move() {
    auto prog = parse(R"(
        void test() {
            int* p = new int(42);
            int* q = move(p);
        }
    )");
    BorrowChecker bc;
    bc.check(prog);
    assert(bc.errors.empty());
    std::cout << "✓ test_valid_move\n";
}

void test_use_after_move() {
    auto prog = parse(R"(
        void test() {
            int* p = new int(42);
            int* q = move(p);
            int* r = move(p);
        }
    )");
    BorrowChecker bc;
    bc.check(prog);
    bool found = false;
    for (auto& e : bc.errors)
        if (e.kind == BorrowError::Kind::UseAfterMove && e.varName == "p")
            found = true;
    assert(found);
    std::cout << "✓ test_use_after_move\n";
}

void test_double_mut_borrow() {
    auto prog = parse(R"(
        void test() {
            int x = 10;
            int* a = &mut x;
            int* b = &mut x;
        }
    )");
    BorrowChecker bc;
    bc.check(prog);
    bool found = false;
    for (auto& e : bc.errors)
        if (e.kind == BorrowError::Kind::MutableBorrowWhileBorrowed)
            found = true;
    assert(found);
    std::cout << "✓ test_double_mut_borrow\n";
}

void test_valid_borrows() {
    auto prog = parse(R"(
        void test() {
            int x = 10;
            int& a = &x;
            int& b = &x;
        }
    )");
    BorrowChecker bc;
    bc.check(prog);
    assert(bc.errors.empty());
    std::cout << "✓ test_valid_borrows (two immutable borrows OK)\n";
}

int main() {
    std::cout << "=== Ferrum Borrow Checker Tests ===\n";
    test_valid_move();
    test_use_after_move();
    test_double_mut_borrow();
    test_valid_borrows();
    std::cout << "All tests passed!\n";
}
