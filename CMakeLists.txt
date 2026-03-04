cmake_minimum_required(VERSION 3.20)
project(dtls_schc C)

set(CMAKE_C_STANDARD 11)

set(WOLFSSL_PREFIX /opt/homebrew/Cellar/wolfssl/5.8.4)

include_directories(${WOLFSSL_PREFIX}/include)
link_directories(${WOLFSSL_PREFIX}/lib)

# libschc - build as static library
file(GLOB SCHC_SOURCES
        libschc/bit_operations.c
        libschc/compressor.c
        libschc/fragmenter.c
        libschc/schc.c
        libschc/rcs.c
)
add_library(schc STATIC ${SCHC_SOURCES})
target_include_directories(schc PUBLIC libschc/ libschc/rules/)

add_executable(server server.c)
target_link_libraries(server wolfssl pthread)

add_executable(client client.c)
target_link_libraries(client wolfssl pthread)