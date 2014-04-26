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
  void checkPreCall(const CallEvent &, CheckerContext &) const;
  void checkPostCall(const CallEvent &, CheckerContext &) const;
  void checkLocation(SVal , bool , const Stmt* , CheckerContext &) const;
};

} 

//checker logic

//check memcpy / memset calls
void NetworkTaintChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

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
    //ConstraintManager &constr = C.getConstraintManager();
    SValBuilder &svalBuilder = C.getSValBuilder();

    //llvm::errs() << "idx is tainted\n";
    
    //what are constraints on Idx? 
    //build a comparson to see if state >= 0
    /*Optional<NonLoc>  constZero = svalBuilder.makeZeroVal(svalBuilder.getArrayIndexType()).getAs<NonLoc>();
    if(!constZero) {
      return;
    }

    Optional<NonLoc>  idxNL = Idx.getAs<NonLoc>();
    if(!idxNL) {
      return;
    }

    SVal  cmpr = svalBuilder.evalBinOpNN(state, BO_GE, *idxNL, *constZero, svalBuilder.getConditionType());

    //build a comparison to see if state < 5000
    llvm::APInt V(32, 6);
    SVal        Val = svalBuilder.makeIntVal(V, false); 

    Optional<NonLoc>  NLVal = Val.getAs<NonLoc>();

    if(!NLVal) {
      return;
    }

    Optional<NonLoc>  NLcmpr = cmpr.getAs<NonLoc>();

    if(!NLcmpr) {
      return;
    }

    SVal  cmprLT = svalBuilder.evalBinOpNN(state, BO_LT, *idxNL, *NLVal, svalBuilder.getConditionType());

    //AND these two expressions together
    Optional<NonLoc>  NLcmprLT = cmprLT.getAs<NonLoc>();

    if(!NLcmprLT) {
      return;
    }

    SVal cmprand = svalBuilder.evalBinOpNN(state, BO_LAnd, *NLcmprLT, *NLcmpr, svalBuilder.getConditionType());

    cmprand.dump();
    llvm::errs() << "\n";

    Optional<NonLoc>  NLcmprand = cmprand.getAs<NonLoc>();

    if(!NLcmprand) {
      return;
    }*/

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

    SVal  cmprLT = svalBuilder.evalBinOpNN(state, BO_GT, *idxNL, *NLVal, svalBuilder.getConditionType());

    Optional<NonLoc>  NLcmprand = cmprLT.getAs<NonLoc>();

    if(!NLcmprand) {
      return;
    }

    //cmprLT.dump();
    //llvm::errs() << "\n";

    //try and assert cmprand
    std::pair<ProgramStateRef,ProgramStateRef>  p = 
      state->assume(*NLcmprand);

    ProgramStateRef trueState = p.first;
    ProgramStateRef falseState = p.second;

    if(trueState) {
      llvm::errs() << "unsafe!\n";
      //report a bug!
    }

    /*if(trueState) {
      llvm::errs() << "condition is true in this state\n";
      trueState->dump();
      llvm::errs() << "\n";
    } else {
      llvm::errs() << "condition is not true in this state\n";
    }

    if(falseState) {
      llvm::errs() << "condition is false in this state\n";
      falseState->dump();
      llvm::errs() << "\n";
    } else {
      llvm::errs() << "condition is not false in this state\n";
    }*/

    //state->dump();
    //llvm::errs() << "\n";
  }

  return;
}

//check for htonl/htons 
void NetworkTaintChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  //is htons or htonl?
  const IdentifierInfo *ID = Call.getCalleeIdentifier();

  if(ID->getName() == "ntohl" || ID->getName() == "ntohl") {
    ProgramStateRef State = C.getState();

    //llvm::errs() << "found ntohl/s call\n";
    //taint the value written to by this call 
    SymbolRef Sym = Call.getReturnValue().getAsSymbol(); 

    if(Sym) {
      //Sym->dump();
      //llvm::errs() << "\n";
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
