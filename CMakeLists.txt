#
# PQLite - Post-Quantum SQLite
# Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
#
# CMake build system for PQLite.
# PQLite is a product of Dyber, Inc.
#
# Usage:
#   cmake -B build -DPQLITE_PQC=ON -DCMAKE_BUILD_TYPE=Release
#   cmake --build build
#
# Options:
#   -DPQLITE_PQC=ON|OFF      Enable/disable PQC encryption (default: ON)
#   -DPQLITE_BUILD_SHELL=ON  Build the pqlite3 CLI shell (default: ON)
#

cmake_minimum_required(VERSION 3.16)
project(PQLite VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)

# ============================================================
# Options
# ============================================================
option(PQLITE_PQC "Enable Post-Quantum Cryptography" ON)
option(PQLITE_BUILD_SHELL "Build the pqlite3 command-line shell" ON)
option(PQLITE_THREADSAFE "Enable thread-safe mode" ON)

# ============================================================
# Step 1: Build the Lemon parser generator
# ============================================================
add_executable(lemon tool/lemon.c)
target_include_directories(lemon PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tool)

# ============================================================
# Step 2: Generate parse.c and parse.h from parse.y using Lemon
# ============================================================
set(PARSE_C ${CMAKE_CURRENT_BINARY_DIR}/parse.c)
set(PARSE_H ${CMAKE_CURRENT_BINARY_DIR}/parse.h)

add_custom_command(
  OUTPUT ${PARSE_C} ${PARSE_H}
  COMMAND ${CMAKE_COMMAND} -E copy
          ${CMAKE_CURRENT_SOURCE_DIR}/src/parse.y
          ${CMAKE_CURRENT_BINARY_DIR}/parse.y
  COMMAND ${CMAKE_COMMAND} -E copy
          ${CMAKE_CURRENT_SOURCE_DIR}/tool/lempar.c
          ${CMAKE_CURRENT_BINARY_DIR}/lempar.c
  COMMAND lemon -s ${CMAKE_CURRENT_BINARY_DIR}/parse.y
  DEPENDS lemon src/parse.y tool/lempar.c
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMENT "Generating parse.c from parse.y via Lemon"
)

# ============================================================
# Step 3: Generate shell.c from shell.c.in (simple copy — the
# .in file is already valid C; the template markers are for
# the autosetup build, not for CMake configure_file)
# ============================================================
set(SHELL_C ${CMAKE_CURRENT_BINARY_DIR}/shell.c)

add_custom_command(
  OUTPUT ${SHELL_C}
  COMMAND ${CMAKE_COMMAND} -E copy
          ${CMAKE_CURRENT_SOURCE_DIR}/src/shell.c.in
          ${SHELL_C}
  DEPENDS src/shell.c.in
  COMMENT "Generating shell.c from shell.c.in"
)

# ============================================================
# Step 4: Generate sqlite3.h from sqlite.h.in
# ============================================================
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/src/sqlite.h.in SQLITE_H_CONTENT)
string(REPLACE "--VERS--" "3.53.0" SQLITE_H_CONTENT "${SQLITE_H_CONTENT}")
string(REPLACE "--VERSION-NUMBER--" "3053000" SQLITE_H_CONTENT "${SQLITE_H_CONTENT}")
string(REPLACE "--SOURCE-ID--" "PQLite-1.0.0" SQLITE_H_CONTENT "${SQLITE_H_CONTENT}")
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/sqlite3.h "${SQLITE_H_CONTENT}")

# ============================================================
# SQLite core source files (verified to exist in src/)
# ============================================================
set(SQLITE_CORE_SOURCES
  src/alter.c
  src/analyze.c
  src/attach.c
  src/auth.c
  src/backup.c
  src/bitvec.c
  src/btmutex.c
  src/btree.c
  src/build.c
  src/callback.c
  src/carray.c
  src/complete.c
  src/date.c
  src/dbpage.c
  src/dbstat.c
  src/delete.c
  src/expr.c
  src/fault.c
  src/fkey.c
  src/func.c
  src/global.c
  src/hash.c
  src/insert.c
  src/json.c
  src/legacy.c
  src/loadext.c
  src/main.c
  src/malloc.c
  src/mem0.c
  src/mem1.c
  src/mem2.c
  src/mem3.c
  src/mem5.c
  src/memdb.c
  src/memjournal.c
  src/mutex.c
  src/mutex_noop.c
  src/mutex_unix.c
  src/mutex_w32.c
  src/notify.c
  src/os.c
  src/os_kv.c
  src/os_unix.c
  src/os_win.c
  src/pager.c
  src/pcache.c
  src/pcache1.c
  src/pragma.c
  src/prepare.c
  src/printf.c
  src/random.c
  src/resolve.c
  src/rowset.c
  src/select.c
  src/status.c
  src/table.c
  src/threads.c
  src/tokenize.c
  src/treeview.c
  src/trigger.c
  src/update.c
  src/upsert.c
  src/utf.c
  src/util.c
  src/vacuum.c
  src/vdbe.c
  src/vdbeapi.c
  src/vdbeaux.c
  src/vdbeblob.c
  src/vdbemem.c
  src/vdbesort.c
  src/vdbetrace.c
  src/vdbevtab.c
  src/vtab.c
  src/wal.c
  src/walker.c
  src/where.c
  src/wherecode.c
  src/whereexpr.c
  src/window.c
  # Generated file:
  ${PARSE_C}
)

# ============================================================
# PQC source files (only when PQLITE_PQC=ON)
# ============================================================
set(PQC_SOURCES
  # Core PQC layer
  src/pqc/pqc_common.c
  src/pqc/pqc_mem.c
  src/pqc/pqc_kem.c
  src/pqc/pqc_sig.c
  # Transparent Database Encryption
  src/pqc/pqc_codec.c
  # Integrity & Signing
  src/pqc/pqc_integrity.c
  src/pqc/pqc_wal_sign.c
  # SQL Functions
  src/pqc/pqc_sql_funcs.c
  # Column-Level Encryption (enterprise)
  src/pqc/pqc_column_encrypt.c
  # Cryptographic Audit Log (enterprise)
  src/pqc/pqc_audit.c
  # Dynamic Data Masking (enterprise)
  src/pqc/pqc_masking.c
  # Key Management (multi-backend)
  src/pqc/pqc_keymanager.c
  # Row-Level Security (enterprise)
  src/pqc/pqc_rls.c
  # FIPS 140-3 Compliance Mode
  src/pqc/pqc_fips.c
  # Encrypted Backup & Restore
  src/pqc/pqc_backup.c
)

# ============================================================
# Compile definitions
# ============================================================
set(PQLITE_DEFINITIONS
  -DSQLITE_CORE
  -DSQLITE_ENABLE_FTS5
  -DSQLITE_ENABLE_JSON1
  -DSQLITE_ENABLE_RTREE
  -DSQLITE_ENABLE_COLUMN_METADATA
  -DSQLITE_ENABLE_DBSTAT_VTAB
  -DSQLITE_ENABLE_STMTVTAB
  -DSQLITE_ENABLE_UPDATE_DELETE_LIMIT
  -DSQLITE_ENABLE_DBPAGE_VTAB
)

if(PQLITE_THREADSAFE)
  list(APPEND PQLITE_DEFINITIONS -DSQLITE_THREADSAFE=1)
else()
  list(APPEND PQLITE_DEFINITIONS -DSQLITE_THREADSAFE=0)
endif()

# ============================================================
# PQLite library
# ============================================================
set(ALL_SOURCES ${SQLITE_CORE_SOURCES})

if(PQLITE_PQC)
  list(APPEND ALL_SOURCES ${PQC_SOURCES})
  list(APPEND PQLITE_DEFINITIONS -DPQLITE_ENABLE_PQC)

  # Find liboqs
  find_package(PkgConfig)
  if(PkgConfig_FOUND)
    pkg_check_modules(LIBOQS REQUIRED liboqs)
  else()
    find_path(LIBOQS_INCLUDE_DIRS oqs/oqs.h
      PATHS /usr/local/include /usr/include
            $ENV{LIBOQS_DIR}/include)
    find_library(LIBOQS_LIBRARIES NAMES oqs
      PATHS /usr/local/lib /usr/lib
            $ENV{LIBOQS_DIR}/lib)
  endif()

  # Find OpenSSL (for AES-256-GCM, PBKDF2, HKDF, HMAC)
  find_package(OpenSSL REQUIRED)
endif()

# Static library
add_library(pqlite3 STATIC ${ALL_SOURCES})
target_compile_definitions(pqlite3 PRIVATE ${PQLITE_DEFINITIONS})
target_include_directories(pqlite3 PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_BINARY_DIR}
)

if(PQLITE_PQC)
  target_include_directories(pqlite3 PRIVATE
    ${LIBOQS_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src/pqc
  )
  target_link_libraries(pqlite3 PRIVATE
    ${LIBOQS_LIBRARIES}
    OpenSSL::Crypto
  )
endif()

# Platform libraries
if(UNIX)
  target_link_libraries(pqlite3 PRIVATE pthread dl m)
endif()

# ============================================================
# pqlite3 CLI shell
# ============================================================
if(PQLITE_BUILD_SHELL)
  add_executable(pqlite3_shell ${SHELL_C})
  target_compile_definitions(pqlite3_shell PRIVATE ${PQLITE_DEFINITIONS})
  target_include_directories(pqlite3_shell PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}
  )
  target_link_libraries(pqlite3_shell PRIVATE pqlite3)
  set_target_properties(pqlite3_shell PROPERTIES OUTPUT_NAME pqlite3)

  if(PQLITE_PQC)
    target_include_directories(pqlite3_shell PRIVATE
      ${LIBOQS_INCLUDE_DIRS}
      ${OPENSSL_INCLUDE_DIR}
      ${CMAKE_CURRENT_SOURCE_DIR}/src/pqc
    )
  endif()

  if(UNIX)
    find_library(READLINE_LIB readline)
    if(READLINE_LIB)
      target_compile_definitions(pqlite3_shell PRIVATE -DHAVE_READLINE)
      target_link_libraries(pqlite3_shell PRIVATE ${READLINE_LIB})
    endif()
  endif()
endif()

# ============================================================
# Install
# ============================================================
install(TARGETS pqlite3
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/sqlite3.h DESTINATION include RENAME pqlite3.h)

if(PQLITE_BUILD_SHELL)
  install(TARGETS pqlite3_shell RUNTIME DESTINATION bin)
endif()

# ============================================================
# Summary
# ============================================================
message(STATUS "")
message(STATUS "  PQLite ${PROJECT_VERSION} - Post-Quantum SQLite")
message(STATUS "  Copyright (c) 2025-2026 Dyber, Inc.")
message(STATUS "  ==========================================")
message(STATUS "  PQC encryption:  ${PQLITE_PQC}")
message(STATUS "  Thread-safe:     ${PQLITE_THREADSAFE}")
message(STATUS "  Build shell:     ${PQLITE_BUILD_SHELL}")
if(PQLITE_PQC)
  message(STATUS "  liboqs:          ${LIBOQS_LIBRARIES}")
  message(STATUS "  OpenSSL:         ${OPENSSL_CRYPTO_LIBRARY}")
endif()
message(STATUS "")
