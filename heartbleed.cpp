#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {

class NetworkTaintChecker: public Checker < check::PreCall, check::PostCall > {
  mutable OwningPtr<BugType> BT;

public:
  //void checkPreStmt(const CallExpr *CE, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  //void checkBranchCondition(const Stmt *Condition, CheckerContext &Ctx) const;
};

} 

//checker logic

//check memcpy / memset calls
void NetworkTaintChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {

  return;
}

//check for htonl/htons 
void NetworkTaintChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {

  return;
}

// Register plugin!
extern "C"
void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<NetworkTaintChecker>("security.NetworkTaint", "my example checker");
}

extern "C"
const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
