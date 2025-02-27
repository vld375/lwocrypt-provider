include(GNUInstallDirs)
execute_process(
  COMMAND git log -1 --format=%h
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_COMMIT_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
if (USE_ENCODING_LIB)
  include(ExternalProject)
  set(encoder_LIBRARY ${CMAKE_BINARY_DIR}/install/lib/${CMAKE_STATIC_LIBRARY_PREFIX}qsc_key_encoder${CMAKE_STATIC_LIBRARY_SUFFIX})
  set(encoder_LIBRARY_INCLUDE ${CMAKE_BINARY_DIR}/install/include)
  ExternalProject_Add(encoder
      GIT_REPOSITORY https://github.com/Quantum-Safe-Collaboration/qsc-key-encoder.git
      GIT_TAG main
      CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/install -DCMAKE_BUILD_TYPE=Release
      UPDATE_DISCONNECTED 1
      BUILD_BYPRODUCTS ${encoder_LIBRARY}
  )
  add_library(qsc_key_encoder STATIC IMPORTED)
  set_target_properties(qsc_key_encoder PROPERTIES IMPORTED_LOCATION ${encoder_LIBRARY})
endif()
add_definitions(-DLWOCRYPTPROVIDER_VERSION_TEXT="${LWOCRYPTPROVIDER_VERSION_TEXT}")
message(STATUS "Building commit ${GIT_COMMIT_HASH} in ${CMAKE_SOURCE_DIR}")
add_definitions(-DLWOCRYPT_PROVIDER_COMMIT=" \(${GIT_COMMIT_HASH}\)")
set(PROVIDER_SOURCE_FILES
  lwocryptprov.c lwocryptprov_capabilities.c lwocryptprov_keys.c
  lwocrypt_kmgmt.c lwocrypt_sig.c lwocrypt_kem.c
  lwocrypt_encode_key2any.c lwocrypt_endecoder_common.c lwocrypt_decode_der2key.c lwocryptprov_bio.c
  lwocryptprov.def
)
set(PROVIDER_HEADER_FILES
  lwocrypt_prov.h lwocrypt_endecoder_local.h
)
add_library(lwocryptprovider SHARED ${PROVIDER_SOURCE_FILES})
if (USE_ENCODING_LIB)
  add_dependencies(lwocryptprovider encoder)
endif()
set_target_properties(lwocryptprovider
    PROPERTIES
    PREFIX ""
    OUTPUT_NAME "lwocryptprovider"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    VERSION ${LWOCRYPTPROVIDER_VERSION_TEXT}
    SOVERSION 1
    # For Windows DLLs
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
target_link_libraries(lwocryptprovider LWOCRYPT::lwocrypt ${OPENSSL_CRYPTO_LIBRARY} ${LWOCRYPT_ADDL_SOCKET_LIBS})
if (USE_ENCODING_LIB)
  target_link_libraries(lwocryptprovider qsc_key_encoder)
  target_include_directories(lwocryptprovider PRIVATE ${encoder_LIBRARY_INCLUDE})
endif()
install(TARGETS lwocryptprovider
        LIBRARY DESTINATION "${OPENSSL_MODULES_PATH}"
        RUNTIME DESTINATION "${OPENSSL_MODULES_PATH}")
set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_VENDOR "www.openquantumsafe.org")
set(CPACK_PACKAGE_VERSION ${LWOCRYPTPROVIDER_VERSION_TEXT})
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6, openssl (>= 3.0.0), liblwocrypt (>= 0.8.0)")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "www.openquantumsafe.org")
include(CPack)

