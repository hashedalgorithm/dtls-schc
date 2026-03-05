cmake_minimum_required(VERSION 3.20)
project(dtls_schc C)

set(CMAKE_C_STANDARD 11)

# ── wolfSSL ──────────────────────────────────────────────────────────
set(WOLFSSL_PREFIX /opt/homebrew/Cellar/wolfssl/5.8.4)
include_directories(${WOLFSSL_PREFIX}/include)
link_directories(${WOLFSSL_PREFIX}/lib)

file(GLOB SCHC_SOURCES
        schc-mini/schc_mini.c
)

# ── SCHC-MINI integration layer ───────────────────────────────────────────
set(DTLS_SCHC_SOURCES schc-mini/schc_mini.c)

# ── server ───────────────────────────────────────────────────────────
add_executable(server server.c ${DTLS_SCHC_SOURCES})
target_include_directories(server PRIVATE . schc-mini/)
target_compile_definitions(server PRIVATE USE_DTLS=1)
target_link_libraries(server wolfssl pthread)

# ── client ───────────────────────────────────────────────────────────
add_executable(client client.c ${DTLS_SCHC_SOURCES})
target_include_directories(client PRIVATE . schc-mini/)
target_compile_definitions(client PRIVATE USE_DTLS=1)
target_link_libraries(client wolfssl pthread)
