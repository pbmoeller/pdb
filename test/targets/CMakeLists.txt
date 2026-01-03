function(add_test_cpp_target name)
    add_executable(${name} "${name}.cpp")
    target_compile_options(${name}
        PRIVATE
            -pie
            -g -O0
        )
    add_dependencies(pdb_test ${name})
endfunction()

function(add_test_asm_target name)
    add_executable(${name} "${name}.s")
    target_compile_options(${name}
        PRIVATE
            -pie
        )
    add_dependencies(pdb_test ${name})
endfunction()


add_test_cpp_target(run_endlessly)
add_test_cpp_target(end_immediately)
add_test_cpp_target(hello_pdb)

add_test_asm_target(reg_write)
add_test_asm_target(reg_read)
