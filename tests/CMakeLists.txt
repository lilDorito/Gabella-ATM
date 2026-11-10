find_package(Threads REQUIRED)

function(gabella_test name)
    cmake_parse_arguments(T "" "" "SOURCES;DEPS" ${ARGN})
    gabella_executable(${name}
        SOURCES ${T_SOURCES}
        DEPS ${T_DEPS})
    target_include_directories(${name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/support")
    add_test(NAME ${name} COMMAND ${name})
endfunction()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test_crypto.cpp")
    gabella_test(test_crypto
        SOURCES crypto/test_crypto.cpp
        DEPS Gabella::common Gabella::crypto)
endif()

gabella_test(test_audit
    SOURCES audit/test_audit.cpp
    DEPS Gabella::common Gabella::crypto Gabella::audit Threads::Threads)

gabella_test(test_atm
    SOURCES atm/test_atm.cpp
    DEPS Gabella::common Gabella::crypto Gabella::audit Gabella::access Gabella::atm)

gabella_test(test_access
    SOURCES access/test_access.cpp
    DEPS Gabella::common Gabella::audit Gabella::access)

gabella_test(test_server_core
    SOURCES server/test_server_core.cpp
    DEPS Gabella::common Gabella::crypto Gabella::audit Gabella::access Gabella::server_api Gabella::server)

gabella_test(test_server_audit
    SOURCES server/test_server_audit.cpp
    DEPS Gabella::common Gabella::crypto Gabella::audit Gabella::access Gabella::server_api Gabella::server)

gabella_test(test_server_auth
    SOURCES server/test_server_auth.cpp
    DEPS Gabella::common Gabella::crypto Gabella::audit Gabella::access Gabella::server_api Gabella::server)

gabella_test(test_seed_db
    SOURCES server/test_seed_db.cpp "${CMAKE_SOURCE_DIR}/tools/seed_db/DemoData.cpp"
    DEPS Gabella::common Gabella::crypto Gabella::audit Gabella::access Gabella::server_api Gabella::server)
target_include_directories(test_seed_db PRIVATE "${CMAKE_SOURCE_DIR}/tools/seed_db")
