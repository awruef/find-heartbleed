#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {
class ExampleChecker : public Checker < check::PreStmt<CallExpr> > {
  mutable OwningPtr<BugType> BT;

public:
  void checkPreStmt(const CallExpr *CE, CheckerContext &C) const;
};
} 

void ExampleChecker::checkPreStmt(const CallExpr *CE, CheckerContext &C) const {

  return;
}

// Register plugin!
extern "C"
void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<ExampleChecker>("example.ExampleChecker", "my example checker");
}

extern "C"
const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
