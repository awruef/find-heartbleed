cmake_minimum_required (VERSION 2.8)

project (find-heartbleed)
set(CMAKE_BUILD_TYPE Release)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "/usr/share/llvm/cmake")

find_package(LLVM)
include(AddLLVM)

set( LLVM_LINK_COMPONENTS support mc)

add_llvm_loadable_module( find-heartbleed heartbleed.cpp)

