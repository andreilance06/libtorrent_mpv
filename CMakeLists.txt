cmake_minimum_required(VERSION 3.30)
project(libtorrent_mpv)

set(CMAKE_CXX_STANDARD 17)

include(CheckIPOSupported)
check_ipo_supported(RESULT lto_supported OUTPUT output)
if(lto_supported)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
else()
    message(WARNING "IPO is not supported: ${output}")
endif()

set(Boost_DIR "../boost_1_88_0/stage/lib/cmake/Boost-1.88.0/")
cmake_policy(SET CMP0167 NEW)
find_package(Boost REQUIRED COMPONENTS system filesystem json program_options url)

add_subdirectory("../libtorrent/" libtorrent)

file(GLOB_RECURSE US_SOURCES "../uSockets/src/*.c")
add_library(uSockets ${US_SOURCES})
target_include_directories(uSockets PUBLIC "../uSockets/src"/)
target_compile_definitions(uSockets PRIVATE LIBUS_NO_SSL)

find_package(ZLIB REQUIRED)
add_library(uWebSockets INTERFACE)
target_include_directories(uWebSockets INTERFACE "../uWebSockets/src/")
target_link_libraries(uWebSockets INTERFACE uSockets ${ZLIB_LIBRARIES})
target_compile_options(uWebSockets INTERFACE -Wno-deprecated-declarations)

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
    torrent-rasterbar
    uWebSockets
    ${Boost_LIBRARIES}
)