# All tests are synthetic. No game data, no dump, no key material — a fresh
# clone runs the full suite with nothing installed and nothing supplied.

add_executable(test_container
    test_container.c
    ${CMAKE_SOURCE_DIR}/tools/armrecomp/container.c
)

target_include_directories(test_container PRIVATE
    ${CMAKE_SOURCE_DIR}/tools/armrecomp
)

# Release configurations define NDEBUG, which compiles every assert() in the
# suite to nothing — the tests then print "all passed" while checking nothing.
# Strip it for test targets. test_container.c also #errors if NDEBUG survives,
# so this cannot silently regress.
target_compile_options(test_container PRIVATE -UNDEBUG)

add_test(NAME container COMMAND test_container)

add_executable(test_inflate
    test_inflate.c
    ${CMAKE_SOURCE_DIR}/tools/armrecomp/inflate.c
)

target_include_directories(test_inflate PRIVATE
    ${CMAKE_SOURCE_DIR}/tools/armrecomp
)

target_compile_options(test_inflate PRIVATE -UNDEBUG)

add_test(NAME inflate COMMAND test_inflate)

add_executable(test_decode
    test_decode.c
    ${CMAKE_SOURCE_DIR}/tools/armrecomp/decode.c
)

target_include_directories(test_decode PRIVATE
    ${CMAKE_SOURCE_DIR}/tools/armrecomp
)

target_compile_options(test_decode PRIVATE -UNDEBUG)

add_test(NAME decode COMMAND test_decode)
