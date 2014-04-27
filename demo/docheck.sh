#!/bin/bash
PLUGIN_PATH=$PWD/../../build/find-heartbleed.so
echo $PLUGIN_PATH
#make clean
scan-build -load-plugin $PLUGIN_PATH -enable-checker security.NetworkTaint make
