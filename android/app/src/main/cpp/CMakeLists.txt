cmake_minimum_required(VERSION 3.22.1)
project(jiter_native LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

get_filename_component(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../.." ABSOLUTE)
set(NATIVE_C_DIR "${REPO_ROOT}/engine-native/c")
set(NATIVE_CPP_DIR "${REPO_ROOT}/engine-native/cpp")
set(RUST_INCLUDE_DIR "${REPO_ROOT}/engine-rust/include")
set(RUST_STATIC_LIB "${CMAKE_CURRENT_SOURCE_DIR}/prebuilt/${ANDROID_ABI}/libjiter_math.a")

add_library(jiter_native SHARED
    "${NATIVE_C_DIR}/src/jiter_packet.c"
    "${NATIVE_CPP_DIR}/src/jiter_scheduler.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/jiter_jni.cpp"
)

target_include_directories(jiter_native PRIVATE
    "${NATIVE_C_DIR}/include"
    "${NATIVE_CPP_DIR}/include"
    "${RUST_INCLUDE_DIR}"
)

target_compile_options(jiter_native PRIVATE -O2 -Wall -Wextra)

find_library(log-lib log)

if(EXISTS "${RUST_STATIC_LIB}")
    message(STATUS "JITER: Linking Rust mathematical engine staticlib: ${RUST_STATIC_LIB}")
    add_library(jiter_math STATIC IMPORTED)
    set_target_properties(jiter_math PROPERTIES IMPORTED_LOCATION "${RUST_STATIC_LIB}")
    target_compile_definitions(jiter_native PRIVATE JITER_HAS_RUST_MATH=1)
    target_link_libraries(jiter_native jiter_math ${log-lib})
else()
    message(STATUS "JITER: Rust staticlib not found at ${RUST_STATIC_LIB}; building C/C++ network engine only (Kotlin math fallback active)")
    target_compile_definitions(jiter_native PRIVATE JITER_HAS_RUST_MATH=0)
    target_link_libraries(jiter_native ${log-lib})
endif()
