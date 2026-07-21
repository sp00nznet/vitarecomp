# armrecomp â€” the toolkit CLI. No external dependencies.

add_executable(armrecomp
    main.c
    container.c
    inflate.c
    decode.c
    module.c
    analyze.c
    emit.c
    nids.c
)

target_include_directories(armrecomp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
