cmake_minimum_required(VERSION 3.21)

project(stagdog LANGUAGES CXX)


set (SOURCES 
    src/sha1.cpp
)

set (TEST_SOURCES 
    tests/test_main.cpp
    tests/sha1_test.cpp
)

add_executable(${PROJECT_NAME}_tests ${SOURCES} ${TEST_SOURCES})
target_include_directories(${PROJECT_NAME}_tests PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include/)
target_compile_options(${PROJECT_NAME}_tests PUBLIC -std=c++17 -v)

add_custom_target(test_runner 
    COMMAND ${PROJECT_NAME}_tests 
    DEPENDS ${PROJECT_NAME}_tests)

enable_testing()
add_test(NAME UnitTests COMMAND ${PROJECT_NAME}_tests)