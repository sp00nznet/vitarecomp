# armrecomp — the toolkit CLI. No external dependencies.

add_executable(armrecomp
    main.c
    container.c
)

target_include_directories(armrecomp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
