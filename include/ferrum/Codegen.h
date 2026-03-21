#pragma once
#include "ferrum/AST.h"
#include "ferrum/TypeChecker.h"

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Type.h>

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>

namespace ferrum {

class Codegen {
public:
    struct CodegenError {
        int line;
        std::string message;
    };
    std::vector<CodegenError> errors;

    explicit Codegen(const std::string& moduleName, TypeChecker& tc);

    void generate(const Program& prog);

    // Emit LLVM IR as text
    std::string getIR() const;

    // Write IR to a file; return false on error
    bool writeIR(const std::string& path) const;

private:
    llvm::LLVMContext ctx;
    std::unique_ptr<llvm::Module> mod;
    std::unique_ptr<llvm::IRBuilder<>> builder;
    TypeChecker& tc;

    // Per-variable info in the current function
    struct VarInfo {
        llvm::Value* addr   = nullptr; // alloca (address of the variable slot)
        llvm::Type*  type   = nullptr; // LLVM type of the VALUE stored in addr
        bool isHeap         = false;   // value is a heap pointer (from 'new')
        bool isMoved        = false;   // ownership transferred out
    };

    // Scope stack for codegen
    struct Scope {
        std::unordered_map<std::string, VarInfo> vars;
        bool cleanupDone = false;
    };
    std::vector<Scope> scopes;

    // Known declared functions in the module
    std::unordered_map<std::string, llvm::Function*> functions;

    // Imported C headers (affects which externs we pre-declare)
    std::vector<std::string> importedHeaders;

    // ── Type helpers ──────────────────────────────────────────
    llvm::Type* i8Ty()   { return llvm::Type::getInt8Ty(ctx); }
    llvm::Type* i32Ty()  { return llvm::Type::getInt32Ty(ctx); }
    llvm::Type* i64Ty()  { return llvm::Type::getInt64Ty(ctx); }
    llvm::Type* f64Ty()  { return llvm::Type::getDoubleTy(ctx); }
    llvm::Type* i1Ty()   { return llvm::Type::getInt1Ty(ctx); }
    llvm::Type* voidTy() { return llvm::Type::getVoidTy(ctx); }
    llvm::Type* ptrTy()  { return llvm::PointerType::get(ctx, 0); }

    llvm::Type* toLLVM(const TypeRef& ref);
    llvm::Type* toLLVM(const FerType& ft);
    uint64_t    sizeOf(llvm::Type* ty);

    // ── Scope helpers ─────────────────────────────────────────
    void pushScope();
    void popScope(llvm::Function* func);      // emits free() for heap vars
    void declareVar(const std::string& name, VarInfo info);
    VarInfo* lookupVar(const std::string& name);

    // Emit cleanup (free heap vars) for all active scopes — used before return
    void emitCleanupAll(llvm::Function* func);

    // ── Known extern declarations ─────────────────────────────
    llvm::Function* getOrDeclarePrintf();
    llvm::Function* getOrDeclareMalloc();
    llvm::Function* getOrDeclareFree();
    llvm::Function* getOrDeclareFunction(const std::string& name,
                                         llvm::FunctionType* ftype,
                                         bool variadic = false);

    // ── Code generation ───────────────────────────────────────
    void genDecl(const Decl& decl);
    void genStmt(const Stmt& stmt, llvm::Function* func);

    // Returns the VALUE of the expression (not the address)
    llvm::Value* genExpr(const Expr& expr, llvm::Function* func);

    // Returns the alloca address of a variable (for taking its address)
    llvm::Value* getVarAddr(const std::string& name);

    void addError(int line, const std::string& msg);
};

} // namespace ferrum
