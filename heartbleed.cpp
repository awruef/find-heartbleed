/*
Copyright (c) 2014, Andrew Ruef
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, 
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, 
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this 
   list of conditions and the following disclaimer in the documentation and/or other 
   materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED 
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN 
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH 
DAMAGE.
*/

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
    this->BT.reset(new BugType("Tainted dereference", "AWR Custom Analyzer"));
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
    //so 5000 is chosen as an arbitrary value. reall what we should do is compare
    //the range on the value with the range of the memory object pointed to by
    //either the base pointer, in an array dereference, or the first and second 
    //parameters to memcpy, in a call to memcpy. however, frequently this information
    //is opaque to the analyzer. what I mostly wanted to answer was, show me locations
    //in the code where NO constraints, practically, had been applied to the size. 
    //this would still permit technically incorrect constraints to be passed, so
    //there is room for improvement, but I think that generally, something sound is
    //unattainable here so we just do what we can in the time allotted
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

    Optional<NonLoc>  idxNL = Idx.getAs<NonLoc>();

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
  //is htons or htonl?
  const IdentifierInfo *ID = Call.getCalleeIdentifier();

  if(ID == NULL) {
    return;
  }

  if(ID->getName() == "ntohl" || ID->getName() == "xyzzy" || ID->getName() == "ntohs") {
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
  registry.addChecker<NetworkTaintChecker>("security.awr.NetworkTaint", "heartbleed checker");
}

extern "C"
const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
