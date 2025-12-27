add_library(libpdb
    "libpdb.cpp"
)
add_library(pdb::libpdb ALIAS libpdb)

set_target_properties(
    libpdb
        PROPERTIES OUTPUT_NAME "pdb"
)

target_compile_features(
    libpdb
        PUBLIC
            cxx_std_20
)

target_include_directories(
    libpdb
        PUBLIC
            "$<INSTALL_INTERFACE:include>"
            "$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>"
        PRIVATE
            "${CMAKE_SOURCE_DIR}/src/include"
)

include(GNUInstallDirs)
install(
    TARGETS libpdb
    EXPORT pdb-targets
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

install(
    DIRECTORY "${CMAKE_SOURCE_DIR}/include/"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

install(
    EXPORT pdb-targets
    FILE pdb-config.cmake
    NAMESPACE pdb::
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/pdb"
)
