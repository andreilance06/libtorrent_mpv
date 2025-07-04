cmake_minimum_required(VERSION 3.30)
project(libtorrent_mpv)

set(CMAKE_CXX_STANDARD 17)

include(CheckIPOSupported)
include(FetchContent)
check_ipo_supported(RESULT lto_supported OUTPUT output)
if(lto_supported)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
else()
    message(WARNING "IPO is not supported: ${output}")
endif()

# Boost
set(Boost_DIR "../boost_1_88_0/stage/lib/cmake/Boost-1.88.0/")
cmake_policy(SET CMP0167 NEW)
find_package(Boost REQUIRED COMPONENTS system filesystem json program_options url)

# libtorrent
FetchContent_Declare(
    libtorrent
    GIT_REPOSITORY "https://github.com/arvidn/libtorrent.git"
    GIT_TAG "v2.0.11"
)
FetchContent_MakeAvailable(libtorrent)

# uSockets
FetchContent_Declare(
    uSockets_content
    GIT_REPOSITORY "https://github.com/uNetworking/uSockets.git"
    GIT_TAG "v0.8.8"
    GIT_SUBMODULES ""
)
FetchContent_MakeAvailable(uSockets_content)
file(GLOB_RECURSE US_SOURCES "${usockets_content_SOURCE_DIR}/src/*.c")
add_library(uSockets ${US_SOURCES})
target_include_directories(uSockets PUBLIC "${usockets_content_SOURCE_DIR}/src/")
target_compile_definitions(uSockets PRIVATE LIBUS_NO_SSL)

# uWebSockets
FetchContent_Declare(
    uWebSockets_content
    GIT_REPOSITORY "https://github.com/uNetworking/uWebSockets.git"
    GIT_TAG "v20.37.0"
    GIT_SUBMODULES ""
)
FetchContent_MakeAvailable(uWebSockets_content)
find_package(ZLIB REQUIRED)
add_library(uWebSockets INTERFACE)
target_include_directories(uWebSockets INTERFACE "${uwebsockets_content_SOURCE_DIR}/src/")
target_link_libraries(uWebSockets INTERFACE uSockets ${ZLIB_LIBRARIES})
target_compile_options(uWebSockets INTERFACE -Wno-deprecated-declarations)

# mDNS
FetchContent_Declare(
    mdns
    GIT_REPOSITORY "https://github.com/kiddigital/mdns_cpp.git"
)
FetchContent_MakeAvailable(mdns)

# range_parser
FetchContent_Declare(
    range_parser
    GIT_REPOSITORY "https://github.com/i96751414/range-parser-cpp.git"
    GIT_TAG "v1.0.1"
)
FetchContent_MakeAvailable(range_parser)

file(GLOB_RECURSE SOURCES "src/*.cpp")
add_executable(libtorrent_mpv ${SOURCES})

target_include_directories(libtorrent_mpv
    PRIVATE
    "include/"
)

target_compile_options(libtorrent_mpv
    PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

target_link_libraries(libtorrent_mpv
    PRIVATE
    ${Boost_LIBRARIES}
    torrent-rasterbar
    uWebSockets
    mdns_cpp
    range_parser
)
