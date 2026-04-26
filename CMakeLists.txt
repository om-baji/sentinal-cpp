cmake_minimum_required(VERSION 3.16)
project(sentinal LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(CURL REQUIRED)

add_library(sentinal_core
    encoder/filling.cpp
    encoder/image.cpp
    encoder/linear.cpp
    utils/http.cpp
)

target_include_directories(sentinal_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(sentinal_core
    PUBLIC
        CURL::libcurl
)

add_executable(sentinal_cli
    cli.cpp
)

target_link_libraries(sentinal_cli
    PRIVATE
        sentinal_core
)
