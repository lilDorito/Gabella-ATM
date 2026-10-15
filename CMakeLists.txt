cmake_minimum_required(VERSION 3.20)

project(GabellaBank VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(GABELLA_BUILD_TESTS "Build unit, integration and attack tests" ON)
option(GABELLA_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer (GCC/Clang)" OFF)

if(MSVC)
    option(GABELLA_WERROR "Treat warnings as errors" OFF)
else()
    option(GABELLA_WERROR "Treat warnings as errors" ON)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(Dependencies)
include(GabellaModule)

add_subdirectory(common)
add_subdirectory(server_api)
add_subdirectory(crypto)
add_subdirectory(audit)
add_subdirectory(access)
add_subdirectory(atm)
add_subdirectory(server)
add_subdirectory(tools)
add_subdirectory(app)

if(GABELLA_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
