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

set(BUILD_SHARED_LIBS OFF)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_DIR "/home/andrei/Documents/repos/boost_1_87_0/stage/lib/cmake/Boost-1.87.0/")
cmake_policy(SET CMP0167 NEW)
find_package(Boost REQUIRED COMPONENTS system filesystem json program_options url)

set(static_runtime ON)
set(deprecated-functions OFF)
set(logging OFF)
add_subdirectory("/home/andrei/Documents/repos/libtorrent" libtorrent)

set(SOURCES
    "src/libtorrent_mpv.cpp"
    "src/alert_handler.cpp"
    "src/range_parser.cpp"
)
include_directories(include)
add_executable(libtorrent_mpv ${SOURCES})

target_compile_options(libtorrent_mpv
    PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

target_link_libraries(libtorrent_mpv
    PRIVATE
    torrent-rasterbar
    ${Boost_LIBRARIES}
)