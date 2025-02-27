if (WIN32)
cmake_minimum_required(VERSION 3.20 FATAL_ERROR)
else()
cmake_minimum_required(VERSION 3.0 FATAL_ERROR)
endif()
project(lwocrypt-provider LANGUAGES C)
set(LWOCRYPTPROVIDER_VERSION_TEXT "0.5.1-dev")
set(CMAKE_C_STANDARD 11)
set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS ON)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Creating Debug build with LWOCRYPT-Debug env vars enabled")
else()
    message(STATUS "Creating Release build")
    add_definitions( -DNDEBUG )
endif()

if(MSVC)
  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} /NODEFAULTLIB:LIBCMT")
  add_definitions(-DLWOCRYPT_PROVIDER_NOATOMIC)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
  set(LWOCRYPT_ADDL_SOCKET_LIBS "ws2_32.lib gdi32.lib crypt32.lib")
else()
  add_compile_options(-Wunused-function)
  set(LWOCRYPT_ADDL_SOCKET_LIBS "")
endif()

option(NOPUBKEY_IN_PRIVKEY "Do not include public keys in private key structures/PKCS#8 " OFF)
if(${NOPUBKEY_IN_PRIVKEY})
    message(STATUS "Build will not store public keys alongside private keys in PKCS#8 structures")
    add_compile_definitions( NOPUBKEY_IN_PRIVKEY )
else()
    message(STATUS "Build will store public keys in PKCS#8 structures")
endif()
option(USE_ENCODING_LIB "Build with external encoding library for SPKI/PKCS#8 " OFF)
if(${USE_ENCODING_LIB})
    message(STATUS "Build will include external encoding library for SPKI/PKCS#8")
    add_compile_definitions( USE_ENCODING_LIB )
else()
    message(STATUS "Build will not include external encoding library for SPKI/PKCS#8")
endif()

include(CheckLibraryExists)
include(CheckFunctionExists)

# Add required includes and install locations for openssl
find_package(OpenSSL 3.0 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
if (WIN32)
# get_filename_component seems to fail when facing windows paths
# so use new(er) cmake_path instruction there
cmake_path(GET OPENSSL_CRYPTO_LIBRARY PARENT_PATH LWOCRYPT_MODULES_PARENT_PATH)
cmake_path(APPEND LWOCRYPT_MODULES_PARENT_PATH "ossl-modules" OUTPUT_VARIABLE OPENSSL_MODULES_PATH)
else()
get_filename_component(OPENSSL_LIB_DIR ${OPENSSL_CRYPTO_LIBRARY} DIRECTORY)
set(OPENSSL_MODULES_PATH ${OPENSSL_LIB_DIR}/ossl-modules)
endif()

# Add required include for liblwocrypt
find_package(liblwocrypt REQUIRED)
get_target_property(LIBLWOCRYPT_INCLUDE_DIR LWOCRYPT::lwocrypt INTERFACE_INCLUDE_DIRECTORIES)
message(STATUS "liblwocrypt found: Include dir at ${LIBLWOCRYPT_INCLUDE_DIR}")
include_directories(${LIBLWOCRYPT_INCLUDE_DIR})

# Provider module
add_subdirectory(lwocryptprov)

# Testing
enable_testing()
add_subdirectory(test)
