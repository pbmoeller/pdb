add_executable(pdb_test
    "pdb_tests.cpp"
)

set_target_properties(
    pdb_test
        PROPERTIES OUTPUT_NAME "pdb-test"
)

target_link_libraries(
    pdb_test
        PRIVATE
            pdb::libpdb
            Catch2::Catch2WithMain
)

add_subdirectory("targets")