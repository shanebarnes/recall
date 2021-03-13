cmake_minimum_required (VERSION 3.0)
project(recall VERSION 0.0.1)

add_library(${PROJECT_NAME} SHARED recall.cpp)
add_executable("leak" leak.cpp)

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -std=c++11 -Wall -Werror")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -export-dynamic -fPIC -ldl -rdynamic -std=c++11 -Wall -Werror")
    #set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -ldl -pedantic-errors -rdynamic -std=c++11 -Wall -Werror")
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${PROJECT_VERSION})
