file(GLOB _seed_db_sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/seed_db/*.cpp")
if(_seed_db_sources)
    gabella_executable(seed_db
        SOURCES ${_seed_db_sources}
        DEPS Gabella::server Gabella::crypto)
endif()
