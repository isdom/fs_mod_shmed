cmake_minimum_required(VERSION 3.14)

project(mod_shmed)

set(CMAKE_CXX_STANDARD 14 CACHE STRING "The C++ version to be used.")

include_directories(/usr/local/freeswitch/include/freeswitch)

ADD_LIBRARY (mod_shmed SHARED mod_share_media.cpp)
