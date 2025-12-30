set(LIBPDB_HEADERS
    "${CMAKE_SOURCE_DIR}/include/libpdb/bit.hpp"
    "${CMAKE_SOURCE_DIR}/include/libpdb/error.hpp"
    "${CMAKE_SOURCE_DIR}/include/libpdb/pipe.hpp"
    "${CMAKE_SOURCE_DIR}/include/libpdb/process.hpp"
    "${CMAKE_SOURCE_DIR}/include/libpdb/registers.hpp"
    "${CMAKE_SOURCE_DIR}/include/libpdb/register_info.hpp"
    "${CMAKE_SOURCE_DIR}/include/libpdb/types.hpp"
    "${CMAKE_SOURCE_DIR}/include/libpdb/detail/registers.inc"
)

set(LIBPDB_SOURCES
    "pipe.cpp"
    "process.cpp"
    "registers.cpp"
)

add_library(libpdb)
add_library(pdb::libpdb ALIAS libpdb)

target_sources(libpdb
    PRIVATE
        ${LIBPDB_SOURCES}
)

target_sources(libpdb
    PUBLIC
        FILE_SET    public_headers
        TYPE        HEADERS
        BASE_DIRS   "${CMAKE_SOURCE_DIR}/include"
        FILES       ${LIBPDB_HEADERS}
)

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
    FILE_SET public_headers
)

install(
    EXPORT pdb-targets
    FILE pdb-config.cmake
    NAMESPACE pdb::
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/pdb"
)
