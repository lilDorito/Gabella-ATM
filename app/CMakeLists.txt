gabella_executable(gabella_bank
    SOURCES main.cpp "${CMAKE_SOURCE_DIR}/tools/seed_db/DemoData.cpp"
    DEPS Gabella::common Gabella::crypto Gabella::audit Gabella::access Gabella::atm Gabella::server_api Gabella::server)
target_include_directories(gabella_bank PRIVATE "${CMAKE_SOURCE_DIR}/tools/seed_db")
