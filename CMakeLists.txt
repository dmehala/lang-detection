cmake_minimum_required(VERSION 3.15...4.0)

project(
  WinSSI
  VERSION 0.1.0
  LANGUAGES CXX
)

add_executable(Injector main.cpp)
set_property(TARGET Injector PROPERTY CXX_STANDARD 20)

add_library(Mylib SHARED my_lib.cpp)
set_property(TARGET Mylib PROPERTY CXX_STANDARD 20)

add_executable(Simple target.cpp)
set_property(TARGET Mylib PROPERTY CXX_STANDARD 20)
