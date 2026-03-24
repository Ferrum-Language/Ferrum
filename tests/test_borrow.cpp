#include "ferrum/Lexer.h"
#include "ferrum/Parser.h"
#include "ferrum/BorrowChecker.h"
#include "ferrum/TypeChecker.h"
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

// ─── Security: unsafe fn call enforcement ─────────────────────────────────────

void test_unsafe_fn_call_outside_block() {
    // Calling an 'unsafe fn' outside an unsafe block must be an error.
    auto prog = parse(R"(
        unsafe void dangerous() {}
        void test() {
            dangerous();
        }
    )");
    BorrowChecker bc;
    bc.check(prog);
    bool found = false;
    for (auto& e : bc.errors)
        if (e.kind == BorrowError::Kind::UnsafeOutsideUnsafeBlock &&
            e.varName == "dangerous")
            found = true;
    assert(found);
    std::cout << "✓ test_unsafe_fn_call_outside_block\n";
}

void test_unsafe_fn_call_inside_block() {
    // Calling an 'unsafe fn' inside an unsafe block must be allowed.
    auto prog = parse(R"(
        unsafe void dangerous() {}
        void test() {
            unsafe { dangerous(); }
        }
    )");
    BorrowChecker bc;
    bc.check(prog);
    bool hasUnsafeError = false;
    for (auto& e : bc.errors)
        if (e.kind == BorrowError::Kind::UnsafeOutsideUnsafeBlock)
            hasUnsafeError = true;
    assert(!hasUnsafeError);
    std::cout << "✓ test_unsafe_fn_call_inside_block\n";
}

// ─── Security: TypeChecker integer overflow & division by zero ────────────────

Program parseAndTypeCheck(const std::string& src, TypeChecker& tc) {
    Lexer lex(src, "<test>");
    auto tokens = lex.tokenize();
    Parser parser(tokens);
    auto prog = parser.parse();
    tc.check(prog);
    return prog;
}

void test_integer_overflow_literal() {
    TypeChecker tc;
    parseAndTypeCheck(R"(
        void test() { int x = 9999999999; }
    )", tc);
    bool found = false;
    for (auto& e : tc.errors)
        if (e.message.find("overflows") != std::string::npos) found = true;
    assert(found);
    std::cout << "✓ test_integer_overflow_literal\n";
}

void test_division_by_zero() {
    TypeChecker tc;
    parseAndTypeCheck(R"(
        void test() { int x = 10 / 0; }
    )", tc);
    bool found = false;
    for (auto& e : tc.errors)
        if (e.message.find("division by zero") != std::string::npos) found = true;
    assert(found);
    std::cout << "✓ test_division_by_zero\n";
}

void test_modulo_by_zero() {
    TypeChecker tc;
    parseAndTypeCheck(R"(
        void test() { int x = 10 % 0; }
    )", tc);
    bool found = false;
    for (auto& e : tc.errors)
        if (e.message.find("division by zero") != std::string::npos) found = true;
    assert(found);
    std::cout << "✓ test_modulo_by_zero\n";
}

void test_gets_blocked() {
    TypeChecker tc;
    parseAndTypeCheck(R"(
        import <stdio.h>;
        void test() {
            char* buf = gets(null);
        }
    )", tc);
    bool found = false;
    for (auto& e : tc.errors)
        if (e.message.find("forbidden function") != std::string::npos &&
            e.message.find("gets") != std::string::npos) found = true;
    assert(found);
    std::cout << "✓ test_gets_blocked\n";
}

void test_strcpy_warning() {
    TypeChecker tc;
    parseAndTypeCheck(R"(
        import <string.h>;
        void test(char* dst, char* src) {
            strcpy(dst, src);
        }
    )", tc);
    bool found = false;
    for (auto& e : tc.errors)
        if (e.message.find("[warning]") != std::string::npos &&
            e.message.find("strcpy") != std::string::npos) found = true;
    assert(found);
    std::cout << "✓ test_strcpy_warning\n";
}

int main() {
    std::cout << "=== Ferrum Borrow Checker Tests ===\n";
    test_valid_move();
    test_use_after_move();
    test_double_mut_borrow();
    test_valid_borrows();
    std::cout << "\n=== Ferrum Security Tests ===\n";
    test_unsafe_fn_call_outside_block();
    test_unsafe_fn_call_inside_block();
    test_integer_overflow_literal();
    test_division_by_zero();
    test_modulo_by_zero();
    test_gets_blocked();
    test_strcpy_warning();
    std::cout << "All tests passed!\n";
}
