#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ConstraintManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"

#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace ento;

namespace {

class NetworkTaintChecker: public Checker < check::PreCall, 
                                            check::PostCall, 
                                            check::Location > {
  mutable OwningPtr<BugType> BT;

public:
  NetworkTaintChecker(void) {
    this->BT.reset(new BugType("Tainted dereference", "Example"));
  }

  void checkPreCall(const CallEvent &, CheckerContext &) const;
  void checkPostCall(const CallEvent &, CheckerContext &) const;
  void checkLocation(SVal , bool , const Stmt* , CheckerContext &) const;
};

} 

//checker logic

//check memcpy / memset calls
void NetworkTaintChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const IdentifierInfo *ID = Call.getCalleeIdentifier();

  if(ID->getName() == "memcpy") {
    //check if the 3rd argument is tainted and constrained 

  }
 
  return;
}

//also check address arithmetic
void NetworkTaintChecker::checkLocation(SVal l, bool isLoad, const Stmt* LoadS,
                                      CheckerContext &C) const {
  const MemRegion *R = l.getAsRegion();
  if (!R) {
    return;
  }

  const ElementRegion *ER = dyn_cast<ElementRegion>(R);
  if (!ER) {
    return;
  }

  DefinedOrUnknownSVal  Idx = ER->getIndex().castAs<DefinedOrUnknownSVal>();
  ProgramStateRef       state = C.getState();

  if(state->isTainted(Idx)) {
    SValBuilder &svalBuilder = C.getSValBuilder();

    //check if the value is constrained 
    llvm::APInt V(32, 5000);
    SVal        Val = svalBuilder.makeIntVal(V, false); 

    Optional<NonLoc>  NLVal = Val.getAs<NonLoc>();

    if(!NLVal) {
      return;
    }

    Optional<NonLoc>  idxNL = Idx.getAs<NonLoc>();
    if(!idxNL) {
      return;
    }

    SVal  cmprLT = svalBuilder.evalBinOpNN( state, 
                                            BO_GT, 
                                            *idxNL, 
                                            *NLVal, 
                                            svalBuilder.getConditionType());

    Optional<NonLoc>  NLcmprand = cmprLT.getAs<NonLoc>();

    if(!NLcmprand) {
      return;
    }

    //try and assert cmprand
    std::pair<ProgramStateRef,ProgramStateRef>  p = 
      state->assume(*NLcmprand);

    ProgramStateRef trueState = p.first;
    ProgramStateRef falseState = p.second;

    if(trueState) {
      //report a bug!
      ExplodedNode *loc = C.generateSink();
      if(loc) {
        BugReport *bug = new BugReport(*this->BT, "Tainted, unconstrained value used in array index", loc);
        C.emitReport(bug);
      }
    }
  }

  return;
}

//check for htonl/htons 
void NetworkTaintChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  //is htons or htonl?
  const IdentifierInfo *ID = Call.getCalleeIdentifier();

  if(ID->getName() == "ntohl" || ID->getName() == "ntohl") {
    ProgramStateRef State = C.getState();

    //taint the value written to by this call 
    SymbolRef Sym = Call.getReturnValue().getAsSymbol(); 

    if(Sym) {
      ProgramStateRef newState = State->addTaint(Sym);
      C.addTransition(newState);
    }
  }

  return;
}

// Register plugin!
extern "C"
void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<NetworkTaintChecker>("security.NetworkTaint", "my example checker");
}

extern "C"
const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
