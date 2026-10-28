function(gabella_apply_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
        if(GABELLA_WERROR)
            target_compile_options(${target} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
        if(GABELLA_WERROR)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endif()

    if(GABELLA_SANITIZE AND NOT MSVC)
        target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    endif()
endfunction()

function(gabella_module name)
    cmake_parse_arguments(MOD "" "" "DEPS" ${ARGN})

    file(GLOB_RECURSE _sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
    file(GLOB_RECURSE _headers CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h")

    set(_target gabella_${name})

    if(_sources)
        add_library(${_target} STATIC ${_sources} ${_headers})
        target_include_directories(${_target}
            PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
            PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(${_target} PUBLIC ${MOD_DEPS})
        gabella_apply_warnings(${_target})
    else()
        add_library(${_target} INTERFACE)
        target_include_directories(${_target} INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/include")
        target_link_libraries(${_target} INTERFACE ${MOD_DEPS})
    endif()

    add_library(Gabella::${name} ALIAS ${_target})
endfunction()

function(gabella_executable name)
    cmake_parse_arguments(EXE "" "" "SOURCES;DEPS" ${ARGN})
    add_executable(${name} ${EXE_SOURCES} "../tests/atm/FakeBank.h" "../tests/atm/FakeServerLink.h" "../tests/atm/test_atm.cpp")
    target_link_libraries(${name} PRIVATE ${EXE_DEPS})
    gabella_apply_warnings(${name})
endfunction()
