#pragma once
#include "ferrum/AST.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <stdexcept>

namespace ferrum {

// ─── Borrow Check Error ───────────────────────────────────────────────────────

struct BorrowError {
    enum class Kind {
        UseAfterMove,
        UseAfterFree,
        DoubleFree,
        MutableBorrowWhileBorrowed,
        MutateWhileBorrowed,
        BorrowOutlivesOwner,
        UnsafeOutsideUnsafeBlock,
    };
    Kind kind;
    std::string varName;
    int line;
    std::string message;
};

// ─── Ownership State ──────────────────────────────────────────────────────────

struct VarState {
    enum class Ownership { Owned, Moved, Borrowed, BorrowedMut };
    Ownership ownership  = Ownership::Owned;
    int borrowCount      = 0;
    bool hasMutBorrow    = false;
    int declLine         = 0;
    bool isHeap          = false;   // allocated with 'new'
    int scopeLevel       = 0;       // scope depth where this var was declared
    // For borrow variables: which variable they borrow from and at which scope level
    std::string borrowsFrom;
    int borrowedScopeLevel = -1;
    bool isMutBorrow     = false;   // true if this variable is a &mut borrow reference
    bool isUnsafePtr     = false;   // declared with 'unsafe' qualifier
};

// ─── Borrow Checker ───────────────────────────────────────────────────────────

class BorrowChecker {
public:
    std::vector<BorrowError> errors;

    void check(const Program& prog);

private:
    // Scope stack: each scope maps name → state
    std::vector<std::unordered_map<std::string, VarState>> scopes;

    int currentScopeLevel = 0;
    int unsafeDepth       = 0;   // > 0 means inside an unsafe block

    bool inUnsafe() const { return unsafeDepth > 0; }

    void pushScope();
    void popScope();   // checks for dangling borrows, drops owned heap vars
    void declareVar(const std::string& name, VarState state);
    VarState* lookupVar(const std::string& name);

    void checkDecl(const Decl& decl);
    void checkStmt(const Stmt& stmt);
    void checkExpr(const Expr& expr);

    // Borrow rules
    void recordBorrow(const std::string& name, bool isMut, int line,
                      const std::string& declaredVar = "");
    void releaseBorrow(const std::string& name, bool isMut);
    void recordMove(const std::string& name, int line);

    void addError(BorrowError::Kind kind, const std::string& var,
                  int line, const std::string& msg);
};

} // namespace ferrum
