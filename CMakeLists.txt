cmake_minimum_required(VERSION 3.20)
project(dtls_schc C)

set(CMAKE_C_STANDARD 11)

# ── wolfSSL ──────────────────────────────────────────────────────────
set(WOLFSSL_PREFIX /opt/homebrew/Cellar/wolfssl/5.8.4)
include_directories(${WOLFSSL_PREFIX}/include)
link_directories(${WOLFSSL_PREFIX}/lib)

# ── libschc ──────────────────────────────────────────────────────────
file(GLOB SCHC_SOURCES
        libschc/bit_operations.c
        libschc/compressor.c
        libschc/fragmenter.c
        libschc/schc.c
        libschc/rcs.c
        libschc/jsmn.c
        libschc/picocoap.c
)

add_library(schc STATIC ${SCHC_SOURCES})
target_include_directories(schc PUBLIC libschc/ libschc/rules/ rules/)
target_compile_definitions(schc PUBLIC USE_DTLS=1)

# ── SCHC integration layer ───────────────────────────────────────────
set(DTLS_SCHC_SOURCES dtls_schc.c)

# ── server ───────────────────────────────────────────────────────────
add_executable(server server.c ${DTLS_SCHC_SOURCES})
target_include_directories(server PRIVATE . libschc/ rules/)
target_compile_definitions(server PRIVATE USE_DTLS=1)
target_link_libraries(server schc wolfssl pthread)

# ── client ───────────────────────────────────────────────────────────
add_executable(client client.c ${DTLS_SCHC_SOURCES})
target_include_directories(client PRIVATE . libschc/ rules/)
target_compile_definitions(client PRIVATE USE_DTLS=1)
target_link_libraries(client schc wolfssl pthread)

# ── measure (no wolfSSL dependency) ──────────────────────────────────
add_executable(measure measure.c ${DTLS_SCHC_SOURCES})
target_include_directories(measure PRIVATE . libschc/ rules/)
target_compile_definitions(measure PRIVATE USE_DTLS=1)
target_link_libraries(measure schc pthread)