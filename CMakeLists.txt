cmake_minimum_required(VERSION 3.20)
project(dtls_schc C)

set(CMAKE_C_STANDARD 11)

set(WOLFSSL_PREFIX /opt/homebrew/Cellar/wolfssl/5.8.4)

include_directories(${WOLFSSL_PREFIX}/include)
link_directories(${WOLFSSL_PREFIX}/lib)

file(GLOB SCHC_SOURCES
        schc-mini/schc_mini.c
)

add_executable(server server.c)
target_link_libraries(server wolfssl pthread)


add_executable(client client.c)
target_link_libraries(client wolfssl pthread)