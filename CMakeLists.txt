cmake_minimum_required(VERSION 3.10)
project(libtorrent_mpv)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)

set(BUILD_SHARED_LIBS OFF)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(BOOST_ROOT "/home/andrei/Documents/repos/boost_1_87_0")
find_package(Boost REQUIRED COMPONENTS system filesystem json program_options url)

set(static_runtime ON)
set(deprecated-functions OFF)
set(logging OFF)
add_subdirectory("/home/andrei/Documents/repos/libtorrent" libtorrent)

set(SOURCES
    src/libtorrent_mpv.cpp
    src/alert_handler.cpp
    src/range_parser.cpp
)
include_directories(include)
add_executable(libtorrent_mpv ${SOURCES})

target_link_libraries(libtorrent_mpv
    PRIVATE
    torrent-rasterbar
    Boost::system
    Boost::filesystem
    Boost::json
    Boost::program_options
    Boost::url
)