#!/bin/bash
scan-build -load-plugin $1 -enable-checker security.awr.NetworkTaint make
