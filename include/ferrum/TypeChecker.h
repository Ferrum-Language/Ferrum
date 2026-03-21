#pragma once
#include "ferrum/AST.h"
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>

namespace ferrum {

// ─── Resolved type representation ─────────────────────────────────────────────

struct FerType {
    enum class Kind {
        Void, Int, Float, Char, Bool,
        Pointer,    // T*
        Borrow,     // T&
        BorrowMut,  // T&mut
        Struct,     // named struct
        Function,   // function type
        Generic,    // unresolved type parameter (T)
    };
    Kind kind = Kind::Void;
    std::string name;                               // struct/generic name
    std::shared_ptr<FerType> inner;                 // for Pointer/Borrow/BorrowMut
    std::vector<std::shared_ptr<FerType>> typeArgs; // for generic instantiation
    std::vector<std::shared_ptr<FerType>> paramTypes;
    std::shared_ptr<FerType> returnType;
    bool isUnsafe = false;

    static std::shared_ptr<FerType> make(Kind k) {
        auto t = std::make_shared<FerType>(); t->kind = k; return t;
    }
    static std::shared_ptr<FerType> makeVoid()    { return make(Kind::Void); }
    static std::shared_ptr<FerType> makeInt()     { return make(Kind::Int); }
    static std::shared_ptr<FerType> makeFloat()   { return make(Kind::Float); }
    static std::shared_ptr<FerType> makeChar()    { return make(Kind::Char); }
    static std::shared_ptr<FerType> makeBool()    { return make(Kind::Bool); }
    static std::shared_ptr<FerType> makeGeneric(const std::string& n) {
        auto t = make(Kind::Generic); t->name = n; return t;
    }
    static std::shared_ptr<FerType> makeStruct(const std::string& n) {
        auto t = make(Kind::Struct); t->name = n; return t;
    }
    static std::shared_ptr<FerType> makePtr(std::shared_ptr<FerType> inner, bool unsafe = false) {
        auto t = make(Kind::Pointer); t->inner = std::move(inner); t->isUnsafe = unsafe; return t;
    }
    static std::shared_ptr<FerType> makeBorrow(std::shared_ptr<FerType> inner, bool mut = false) {
        auto t = make(mut ? Kind::BorrowMut : Kind::Borrow); t->inner = std::move(inner); return t;
    }

    bool isNumeric()     const { return kind == Kind::Int || kind == Kind::Float || kind == Kind::Char; }
    bool isPointerLike() const { return kind == Kind::Pointer || kind == Kind::Borrow || kind == Kind::BorrowMut; }
    bool isGenericParam()const { return kind == Kind::Generic; }

    std::string toString() const;
};

// ─── Type Checker ─────────────────────────────────────────────────────────────

class TypeChecker {
public:
    struct TypeError {
        int line;
        std::string message;
    };
    std::vector<TypeError> errors;

    void check(Program& prog);

    // Used by Codegen to get the resolved type of an expression
    std::shared_ptr<FerType> getExprType(const Expr* e) const;

private:
    struct FuncInfo {
        std::vector<std::shared_ptr<FerType>> paramTypes;
        std::shared_ptr<FerType> returnType;
        std::vector<std::string> typeParams;
        bool isVariadic = false;   // for C vararg functions like printf
        bool isExtern   = false;
    };
    struct StructInfo {
        std::vector<std::string> fieldNames;
        std::vector<std::shared_ptr<FerType>> fieldTypes;
        std::vector<std::string> typeParams;
    };

    std::unordered_map<std::string, FuncInfo>  functions;
    std::unordered_map<std::string, StructInfo> structs;

    // Scope stack: variable name → type
    std::vector<std::unordered_map<std::string, std::shared_ptr<FerType>>> scopes;

    std::shared_ptr<FerType> currentReturnType;

    // Active generic substitution (e.g. T → int while type-checking a generic call)
    std::unordered_map<std::string, std::shared_ptr<FerType>> typeParamSubst;

    // Expression → resolved type (for Codegen)
    std::unordered_map<const Expr*, std::shared_ptr<FerType>> exprTypes;

    void pushScope();
    void popScope();
    void declare(const std::string& name, std::shared_ptr<FerType> type, int line);
    std::shared_ptr<FerType> lookup(const std::string& name, int line);

    std::shared_ptr<FerType> resolveTypeRef(const TypeRef& ref);
    std::shared_ptr<FerType> checkExpr(Expr& expr);
    void checkStmt(Stmt& stmt);

    // First pass: register all top-level signatures
    void collectDecl(const Decl& decl);
    // Second pass: type-check bodies
    void checkDecl(Decl& decl);

    bool typesCompatible(const FerType& a, const FerType& b) const;
    void addError(int line, const std::string& msg);
    void setExprType(const Expr& e, std::shared_ptr<FerType> t);

    // Register known C library functions for a given header
    void registerCHeader(const std::string& header);
};

} // namespace ferrum
