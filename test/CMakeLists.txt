include(GNUInstallDirs)
if (WIN32 OR CYGWIN)
set(LWOCRYPT_PROV_BINARY_DIR ${CMAKE_BINARY_DIR}/bin)
else()
set(LWOCRYPT_PROV_BINARY_DIR ${CMAKE_BINARY_DIR}/lib)
endif()

add_test(
  NAME lwocrypt_signatures
  COMMAND lwocrypt_test_signatures
          "lwocryptprovider"
          "${CMAKE_SOURCE_DIR}/test/lwocrypt.cnf"
)
# openssl under MSVC seems to have a bug registering NIDs:
# It only works when setting OPENSSL_CONF, not when loading the same cnf file:
if (MSVC)
set_tests_properties(lwocrypt_signatures
    PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${LWOCRYPT_PROV_BINARY_DIR};OPENSSL_CONF=${CMAKE_CURRENT_SOURCE_DIR}/openssl-ca.cnf"
)
else()
set_tests_properties(lwocrypt_signatures
    PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${LWOCRYPT_PROV_BINARY_DIR}"
)
endif()

add_executable(lwocrypt_test_signatures lwocrypt_test_signatures.c test_common.c)
target_link_libraries(lwocrypt_test_signatures ${OPENSSL_CRYPTO_LIBRARY} ${LWOCRYPT_ADDL_SOCKET_LIBS})

add_test(
  NAME lwocrypt_kems
  COMMAND lwocrypt_test_kems
          "lwocryptprovider"
          "${CMAKE_SOURCE_DIR}/test/lwocrypt.cnf"
)
# openssl under MSVC seems to have a bug registering NIDs:
# It only works when setting OPENSSL_CONF, not when loading the same cnf file:
if (MSVC)
set_tests_properties(lwocrypt_kems
    PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${LWOCRYPT_PROV_BINARY_DIR};OPENSSL_CONF=${CMAKE_CURRENT_SOURCE_DIR}/openssl-ca.cnf"
)
else()
set_tests_properties(lwocrypt_kems
    PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${LWOCRYPT_PROV_BINARY_DIR}"
)
endif()

add_executable(lwocrypt_test_kems lwocrypt_test_kems.c test_common.c)
target_link_libraries(lwocrypt_test_kems ${OPENSSL_CRYPTO_LIBRARY} ${LWOCRYPT_ADDL_SOCKET_LIBS})

add_test(
    NAME lwocrypt_groups
    COMMAND lwocrypt_test_groups
            "lwocryptprovider"
            "${CMAKE_CURRENT_SOURCE_DIR}/lwocrypt.cnf"
            "${CMAKE_CURRENT_SOURCE_DIR}"
)
# openssl under MSVC seems to have a bug registering NIDs:
# It only works when setting OPENSSL_CONF, not when loading the same cnf file:
if (MSVC)
set_tests_properties(lwocrypt_groups
    PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${LWOCRYPT_PROV_BINARY_DIR};OPENSSL_CONF=${CMAKE_CURRENT_SOURCE_DIR}/openssl-ca.cnf"
)
else()
set_tests_properties(lwocrypt_groups
    PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${LWOCRYPT_PROV_BINARY_DIR}"
)
endif()
add_executable(lwocrypt_test_groups lwocrypt_test_groups.c test_common.c tlstest_helpers.c)
target_link_libraries(lwocrypt_test_groups ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY} ${LWOCRYPT_ADDL_SOCKET_LIBS})

add_test(
    NAME lwocrypt_tlssig
    COMMAND lwocrypt_test_tlssig
            "lwocryptprovider"
            "${CMAKE_CURRENT_SOURCE_DIR}/openssl-ca.cnf"
            "${CMAKE_CURRENT_BINARY_DIR}/tmp"
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
# openssl under MSVC seems to have a bug registering NIDs:
# It only works when setting OPENSSL_CONF, not when loading the same cnf file:
if (MSVC)
set_tests_properties(lwocrypt_tlssig
    PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${LWOCRYPT_PROV_BINARY_DIR};OPENSSL_CONF=${CMAKE_CURRENT_SOURCE_DIR}/openssl-ca.cnf"
)
else()
set_tests_properties(lwocrypt_tlssig
    PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${LWOCRYPT_PROV_BINARY_DIR}"
)
endif()
add_executable(lwocrypt_test_tlssig lwocrypt_test_tlssig.c test_common.c tlstest_helpers.c)
target_link_libraries(lwocrypt_test_tlssig ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY} ${LWOCRYPT_ADDL_SOCKET_LIBS})

add_executable(lwocrypt_test_endecode lwocrypt_test_endecode.c test_common.c)
target_link_libraries(lwocrypt_test_endecode ${OPENSSL_CRYPTO_LIBRARY} ${LWOCRYPT_ADDL_SOCKET_LIBS})
add_test(
  NAME lwocrypt_endecode
  COMMAND lwocrypt_test_endecode
          "lwocryptprovider"
          "${CMAKE_CURRENT_SOURCE_DIR}/openssl-ca.cnf"
)
# openssl under MSVC seems to have a bug registering NIDs:
# It only works when setting OPENSSL_CONF, not when loading the same cnf file:
if (MSVC)
set_tests_properties(lwocrypt_endecode
    PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${LWOCRYPT_PROV_BINARY_DIR};OPENSSL_CONF=${CMAKE_CURRENT_SOURCE_DIR}/openssl-ca.cnf"
)
else()
set_tests_properties(lwocrypt_endecode
    PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${LWOCRYPT_PROV_BINARY_DIR}"
)
endif()
