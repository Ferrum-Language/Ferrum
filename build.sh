#!/bin/bash
# build.sh — Build Ferrum compiler (with LLVM 18)
set -e

CXX=${CXX:-g++}
LLVM_CONFIG=${LLVM_CONFIG:-llvm-config}

LLVM_CXXFLAGS=$($LLVM_CONFIG --cxxflags 2>/dev/null || echo "")
LLVM_LDFLAGS=$($LLVM_CONFIG --ldflags 2>/dev/null || echo "")
LLVM_LIBS=$($LLVM_CONFIG --libs core support irreader 2>/dev/null || echo "-lLLVM-18")
LLVM_SYSLIBS=$($LLVM_CONFIG --system-libs 2>/dev/null || echo "")

CXXFLAGS="-std=c++20 -Iinclude ${LLVM_CXXFLAGS} -fexceptions -O2 -Wall -Wextra -Wno-unused-parameter"
SOURCES="src/lexer/Lexer.cpp src/parser/Parser.cpp src/borrow/BorrowChecker.cpp src/sema/TypeChecker.cpp src/codegen/Codegen.cpp"
LDFLAGS="${LLVM_LDFLAGS} ${LLVM_LIBS} ${LLVM_SYSLIBS}"

mkdir -p build

echo "Building ferrumc..."
$CXX $CXXFLAGS $SOURCES src/driver/main.cpp -o build/ferrumc $LDFLAGS -lstdc++fs
echo "✓ build/ferrumc"

echo "Building tests..."
$CXX $CXXFLAGS $SOURCES tests/test_lexer.cpp  -o build/test_lexer  $LDFLAGS
$CXX $CXXFLAGS $SOURCES tests/test_borrow.cpp -o build/test_borrow $LDFLAGS
echo "✓ build/test_lexer"
echo "✓ build/test_borrow"

echo ""
echo "Running tests..."
./build/test_lexer
./build/test_borrow

echo ""
echo "Done! Use: ./build/ferrumc <file.fe>"
echo "       Or: ./build/ferrumc <file.fe> --emit-ir   (print LLVM IR)"
echo "       Or: ./build/ferrumc <file.fe> -o output   (compile to binary)"
