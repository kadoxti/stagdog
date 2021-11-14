cmake_minimum_required(VERSION 3.21)

project(stagdog LANGUAGES CXX)


set (SOURCES 
    src/sha1.cpp)

set (TEST_SOURCES 
    tests/test_main.cpp
    tests/sha1_test.cpp)

add_executable(${PROJECT_NAME}_tests ${SOURCES} ${TEST_SOURCES})
target_include_directories(${PROJECT_NAME}_tests PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include/)
target_compile_options(${PROJECT_NAME}_tests PUBLIC -std=c++17 -v)


enable_testing()
add_test(NAME Sha1Tests COMMAND ${PROJECT_NAME}_tests [sha1])

# Doxygen
find_package(Doxygen REQUIRED)
if (Doxygen_FOUND)
    add_custom_target(doc ALL
        COMMAND Doxygen ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile 
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} 
        COMMENT "Building documentation with Doxygen" )
endif()