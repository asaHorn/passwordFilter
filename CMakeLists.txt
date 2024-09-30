#
# Asa Horn
# aoh9470@rit.edu
#

# This is the cmake file which I used to compile the project.
# I still don't know how Cmake works
# so half of it is most likely not required


cmake_minimum_required(VERSION 3.23)
project(Passtome)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Target system is not 64-bit")
endif()

set(CMAKE_CXX_STANDARD 17)

set(SOURCES
        library.cpp
        library.h
        )

add_library(filter SHARED ${SOURCES})

# Additional settings to ensure x64 build
set(CMAKE_GENERATOR_PLATFORM x64)

# Optionally set platform-specific compile flags (for Windows 64-bit)
if(MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /machine:x64")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64")
endif()

if(MSVC)
    # Statically link the C Runtime
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

add_executable(test_app test_app.cpp)
add_executable(MicrosoftCryptographicManager helper.cpp)

# Link the test executable with the DLL
target_link_libraries(test_app filter)
target_link_libraries(MicrosoftCryptographicManager winhttp)