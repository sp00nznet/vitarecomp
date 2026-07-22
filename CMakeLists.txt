# vitarecomp â€” a static-recompilation toolkit for PlayStation Vita games.
#
# This file builds two things:
#   1. the `vitarecomp` runtime static library â€” what recompiled game code links
#      against (CPU state, memory, semantic helpers)
#   2. `armrecomp` â€” the tool that turns a Vita module into C
#
# A game repo consumes this repo as a git submodule and does:
#     add_subdirectory(vitarecomp)
#     add_subdirectory(games/<game>)
# and links its host against the `vitarecomp` target.
#
# The core has no external dependencies on purpose. SDL2, zlib and friends only
# ever appear behind an opt-in option, so a fresh clone builds with nothing
# installed. (zlib matters here in a way it did not for psprecomp: SELF segments
# are routinely zlib-compressed *as well as* encrypted. The inflate path is
# opt-in and the container parser reports compression without needing it.)

cmake_minimum_required(VERSION 3.16)
project(vitarecomp C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W3)
    # The generated C is millions of lines; MSVC's default object format
    # cannot hold that many sections.
    add_compile_options(/bigobj)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Wno-unused-parameter)
endif()

# --- the runtime library ------------------------------------------------------
#
# Empty until phase 3. Declared now so a game repo's add_subdirectory() and
# target_link_libraries() are stable from the start.

add_library(vitarecomp STATIC
    src/cpu.c
    src/mem.c
    src/trap.c
    src/loader.c
    src/dispatch.c
)

target_include_directories(vitarecomp PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# --- the recompiler -----------------------------------------------------------

add_subdirectory(tools/armrecomp)

# --- tests (only when vitarecomp is the top-level project, not a submodule) ----

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    enable_testing()
    add_subdirectory(tests)
endif()
