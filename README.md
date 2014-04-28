Heartbleed Static Checker
=========================
This is a static checker for [Heartbleed](http://www.heartbleed.com) type information disclosures written as a plugin to the [clang analyzer framework](http://clang-analyzer.llvm.org/), as described in a recent [blog post](http://blog.trailofbits.com/2014/04/27/using-static-analysis-and-clang-to-find-heartbleed/). It is experimental and unsound. 

Building 
--------
With LLVM installed into /usr, `mkdir build && cmake .. && make` should build the plugin. If LLVM is not installed in /usr, cmake should be invoked with `-DCMAKE_MODULE_PATH=/path/to/llvm/share/llvm/cmake`. It should then build normally. This should also work on OSX though LLVM will need to be installed separately to get both the headers and libraries for checker plugin development as well as the `scan-build` tool.

Running
-------
To run on a demo, run the following command: `cd demo/1/ && ../docheck.sh /the/full/path/to/build/find-heartbleed.so`. Use the same to build openssl.

Debugging Tips
--------------
`scan-build` hooks into the make infrastructure, so only as much code will be built as would be if you ran `make`. So, if you are debugging an analysis and you want to only run the analyzer on one function, or one file, `make` the entire project, `touch` the file in question, and then run `scan-build`. 
