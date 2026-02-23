cmake_minimum_required(VERSION 3.10)
project(cpp_s3_uploader_libcurl_openssl CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(s3_uploader
    src/s3_uploader.cpp
)

target_include_directories(s3_uploader PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(s3_uploader PRIVATE
    CURL::libcurl
    OpenSSL::SSL
    OpenSSL::Crypto
)

add_executable(upload_example
    examples/upload_example.cpp
)

target_link_libraries(upload_example PRIVATE
    s3_uploader
)