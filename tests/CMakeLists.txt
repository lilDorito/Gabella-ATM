find_package(Threads REQUIRED)

function(gabella_test name)
    cmake_parse_arguments(T "" "" "SOURCES;DEPS" ${ARGN})
    gabella_executable(${name}
        SOURCES ${T_SOURCES}
        DEPS ${T_DEPS})
    target_include_directories(${name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/support")
    target_compile_definitions(${name} PRIVATE GABELLA_INVARIANT_THROW_ONLY)
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
