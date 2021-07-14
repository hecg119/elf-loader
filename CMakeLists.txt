cmake_minimum_required(VERSION 3.17)
project(elf_loader)

set(CMAKE_CXX_STANDARD 14)

include_directories(include)
include_directories(${CMAKE_SOURCE_DIR})

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

include(cmake/ELFIO.cmake)

add_executable(elf_loader main.cpp elf/loader.cpp)
target_link_libraries(elf_loader elfio)