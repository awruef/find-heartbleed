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


  bool isArgUnConstrained(Optional<NonLoc>, SValBuilder &, ProgramStateRef) const;
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

bool NetworkTaintChecker::isArgUnConstrained(Optional<NonLoc> Arg, SValBuilder &builder, ProgramStateRef state) const {
  bool  result = false;

  if(Arg) {
    llvm::APInt V(32, 5000);
    SVal        Val = builder.makeIntVal(V, false); 

    Optional<NonLoc>  NLVal = Val.getAs<NonLoc>();

    if(!NLVal) {
      return result;
    }

    SVal  cmprLT = builder.evalBinOpNN( state, 
                                        BO_GT, 
                                        *Arg, 
                                        *NLVal, 
                                        builder.getConditionType());

    Optional<NonLoc>  NLcmprLT = cmprLT.getAs<NonLoc>();

    if(!NLcmprLT) {
      return result;
    }

    std::pair<ProgramStateRef,ProgramStateRef>  p = 
      state->assume(*NLcmprLT);

    ProgramStateRef trueState = p.first;
    
    if(trueState) {
      result = true;
    }
  }

  return result;
}

//check memcpy / memset calls
void NetworkTaintChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const IdentifierInfo *ID = Call.getCalleeIdentifier();

  if(ID == NULL) {
    return;
  }
  if(ID->getName() == "memcpy") {
    //check if the 3rd argument is tainted and constrained 
    SVal            SizeArg = Call.getArgSVal(2);
    ProgramStateRef state =C.getState();

    if(state->isTainted(SizeArg)) {
      SValBuilder       &svalBuilder = C.getSValBuilder();
      Optional<NonLoc>  SizeArgNL = SizeArg.getAs<NonLoc>();

      if(this->isArgUnConstrained(SizeArgNL, svalBuilder, state) == true) {
        ExplodedNode  *loc = C.generateSink();
        if(loc) {
          BugReport *bug = new BugReport(*this->BT, "Tainted, unconstrained value used in memcpy size", loc);
          C.emitReport(bug);
        }
      }
    }
  }
 
  return;
}

//also check address arithmetic
void NetworkTaintChecker::checkLocation(SVal l, bool isLoad, const Stmt* LoadS,
                                      CheckerContext &C) const {
  //llvm::errs() << "checkLocation\n";
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
    Optional<NonLoc>  idxNL = Idx.getAs<NonLoc>();

    if(!idxNL) {
      return;
    }

    state->dump();
    llvm::errs() << "\n";
    if(this->isArgUnConstrained(idxNL, svalBuilder, state) == true) {
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
  //llvm::errs() << "checkPostCall\n";
  //is htons or htonl?
  const IdentifierInfo *ID = Call.getCalleeIdentifier();

  if(ID == NULL) {
    return;
  }

  if(ID->getName() == "ntohl" || ID->getName() == "xyzzy") {
    ProgramStateRef State = C.getState();
    //llvm::errs() << "found call to ntohl\n";
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
