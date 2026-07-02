cmake_minimum_required(VERSION 3.0)
project("Scaner" VERSION 1.0.0)

set(CMAKE_CXX_COMPILER "/usr/bin/g++")
set(CMAKE_C_COMPILER "/usr/bin/gcc")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(TEST_BUILD)
  file(GLOB_RECURSE SOURCE src/test/*.cpp)
else()
  file(GLOB_RECURSE SOURCE src/**.cpp)
  list(FILTER SOURCE EXCLUDE REGEX src/test/.+$)
endif()

file(GLOB_RECURSE INCLUDE "include/**.cpp")

message("Sources: ${SOURCE}")

add_executable(scaner ${SOURCE} ${INCLUDE})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(scaner PRIVATE ssl crypto curl)
# target_link_directories()