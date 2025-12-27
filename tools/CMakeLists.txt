add_executable(pdb
    "pdb.cpp"
)

target_link_libraries(
    pdb
        PRIVATE
            pdb::libpdb
            PkgConfig::libedit
)

include(GNUInstallDirs)
install(
    TARGETS pdb
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)