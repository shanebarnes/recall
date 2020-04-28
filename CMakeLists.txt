cmake_minimum_required (VERSION 3.0)
project(recall VERSION 0.0.1)

add_library(${PROJECT_NAME} SHARED recall.cpp)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -export-dynamic -fPIC -ldl -rdynamic -std=c++11 -Wall")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -ldl -pedantic-errors -rdynamic -std=c++11 -Wall -Werror")
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${PROJECT_VERSION})
