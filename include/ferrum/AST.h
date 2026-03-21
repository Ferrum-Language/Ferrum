#pragma once
#include "ferrum/Token.h"
#include <memory>
#include <vector>
#include <string>
#include <optional>

namespace ferrum {

// Forward declarations
struct Expr;
struct Stmt;
struct Decl;
using ExprPtr = std::unique_ptr<Expr>;
using StmtPtr = std::unique_ptr<Stmt>;
using DeclPtr = std::unique_ptr<Decl>;

// ─── Types ────────────────────────────────────────────────────────────────────

struct TypeRef {
    enum class Kind { Named, Pointer, Borrow, BorrowMut, Array };
    Kind kind;
    std::string name;                       // for Named
    std::unique_ptr<TypeRef> inner;         // for Pointer/Borrow/Array
    bool isUnsafe = false;
    std::string lifetime;                   // for Borrow/BorrowMut: "'a" (empty = anonymous)
    std::vector<TypeRef> typeArgs;          // for generic types: Vec<int>, Pair<T,U>

    static TypeRef named(std::string n) {
        TypeRef t; t.kind=Kind::Named; t.name=std::move(n); return t;
    }
    static TypeRef pointer(TypeRef inner, bool unsafe=false) {
        TypeRef t; t.kind=Kind::Pointer;
        t.inner = std::make_unique<TypeRef>(std::move(inner));
        t.isUnsafe = unsafe;
        return t;
    }
    static TypeRef borrow(TypeRef inner, bool mut=false, std::string lt="") {
        TypeRef t; t.kind = mut ? Kind::BorrowMut : Kind::Borrow;
        t.inner = std::make_unique<TypeRef>(std::move(inner));
        t.lifetime = std::move(lt);
        return t;
    }
};

// ─── Expressions ──────────────────────────────────────────────────────────────

struct Expr {
    enum class Kind {
        IntLit, FloatLit, StringLit, BoolLit, NullLit,
        Ident,
        BinOp, UnaryOp,
        Call, Index, Member,
        Assign,
        New, Move,
        Borrow, BorrowMut,
        Cast,
    };
    Kind kind;
    int line = 0, col = 0;

    // IntLit / FloatLit / StringLit / BoolLit
    long long   intVal   = 0;
    double      floatVal = 0;
    std::string strVal;
    bool        boolVal  = false;

    // Ident
    std::string name;

    // BinOp / UnaryOp
    std::string op;
    ExprPtr lhs, rhs;

    // Call
    ExprPtr callee;
    std::vector<ExprPtr> args;
    std::vector<TypeRef> typeArgs;          // generic call: foo<int>(x)

    // Member / Index
    ExprPtr object;
    std::string field;

    // New / Move / Borrow / Cast
    std::unique_ptr<TypeRef> typeArg;
    ExprPtr inner;
};

// ─── Statements ───────────────────────────────────────────────────────────────

struct Stmt {
    enum class Kind {
        VarDecl, Expr, Return, If, While, For, Block, Import, Unsafe
    };
    Kind kind;
    int line = 0;

    // VarDecl
    std::string varName;
    std::unique_ptr<TypeRef> varType;  // optional (inferred)
    ExprPtr varInit;
    bool isMut = false;

    // Expr / Return
    ExprPtr expr;

    // If
    ExprPtr condition;
    std::unique_ptr<Stmt> thenBranch;
    std::unique_ptr<Stmt> elseBranch;

    // While
    // condition reused
    std::unique_ptr<Stmt> body;

    // For
    std::unique_ptr<Stmt> init;
    // condition reused
    ExprPtr increment;

    // Block
    std::vector<StmtPtr> stmts;

    // Import
    std::string importPath;
    bool importCpp = false;
};

// ─── Declarations ─────────────────────────────────────────────────────────────

struct Param {
    std::string name;
    TypeRef type;
};

struct Decl {
    enum class Kind { Function, Struct, ExternBlock, Import };
    Kind kind;
    int line = 0;

    // Function
    std::string funcName;
    std::vector<std::string> typeParams;    // generic params: <T, U>
    std::vector<Param> params;
    std::unique_ptr<TypeRef> returnType;
    std::unique_ptr<Stmt> funcBody;         // Block stmt
    bool isUnsafe = false;

    // Struct
    std::string structName;
    std::vector<std::string> structTypeParams; // generic params for struct
    std::vector<Param> fields;

    // ExternBlock ("C++" or "C")
    std::string externLang;
    std::vector<DeclPtr> externDecls;

    // Import
    std::string importPath;
    bool isCppHeader = false;
};

// ─── Program ──────────────────────────────────────────────────────────────────

struct Program {
    std::vector<DeclPtr> decls;
};

} // namespace ferrum
