cmake_minimum_required(VERSION 3.14)
project(rsa_toolkit LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra)
# BigInt type-puns its storage through a layout-compatible view; disable
# strict-aliasing optimizations so GCC -O3 keeps it correct.
add_compile_options(-fno-strict-aliasing)

# Optional sanitizer build:  cmake -DENABLE_SANITIZERS=ON ..
option(ENABLE_SANITIZERS "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
if(ENABLE_SANITIZERS)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address,undefined)
endif()

include_directories(${CMAKE_SOURCE_DIR}/include)

# ---- core cryptographic library (no console / file-IO code) ----------------
file(GLOB CORE_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/*.cpp)
add_library(rsacore STATIC ${CORE_SOURCES})

# ---- interactive CLI (console UI + file handling + self-test) --------------
file(GLOB APP_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/app/*.cpp)
add_executable(rsa-cli ${APP_SOURCES} ${CMAKE_SOURCE_DIR}/apps/cli.cpp)
target_link_libraries(rsa-cli PRIVATE rsacore)

# ---- tests -----------------------------------------------------------------
enable_testing()
file(GLOB TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/tests/*.cpp)
foreach(test_src ${TEST_SOURCES})
  get_filename_component(test_name ${test_src} NAME_WE)
  add_executable(${test_name} ${test_src})
  target_link_libraries(${test_name} PRIVATE rsacore)
  add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

# ---- offensive attack demos ------------------------------------------------
file(GLOB ATTACK_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/attacks/*.cpp)
foreach(attack_src ${ATTACK_SOURCES})
  get_filename_component(attack_name ${attack_src} NAME_WE)
  add_executable(${attack_name} ${attack_src})
  target_link_libraries(${attack_name} PRIVATE rsacore)
endforeach()
