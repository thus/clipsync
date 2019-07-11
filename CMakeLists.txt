# clipsync cmake configuration file

cmake_minimum_required(VERSION 2.8)
project(clipsync)

# Set a default build type if none was specified
set(default_build_type "Release")

# Source files
set(SOURCE
    src/clipsync.c
    src/cb.c
    src/murmur3.c
    src/util.c
)

# Set the output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(${PROJECT_SOURCE_DIR}/libs/libclipboard/include)
include_directories(${CMAKE_BINARY_DIR}/libs/libclipboard/include)

add_executable(clipsync ${SOURCE})

# Depends on libclipboard
add_subdirectory(libs/libclipboard)
add_dependencies(clipsync clipboard)
target_link_libraries(clipsync clipboard)

# Depends on libsodium
set(sodium_USE_STATIC_LIBS TRUE)
include("${PROJECT_SOURCE_DIR}/cmake/Findsodium.cmake")
target_link_libraries(clipsync sodium)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_executable(cb_stress_test tools/stress_test.c src/cb.c src/murmur3.c src/util.c)
    target_link_libraries(cb_stress_test clipboard)
    target_link_libraries(cb_stress_test sodium)

    target_compile_options(clipsync PRIVATE -Wall -pedantic)
    target_compile_options(cb_stress_test PRIVATE -Wall -pedantic)
endif()

install(TARGETS clipsync DESTINATION bin)
