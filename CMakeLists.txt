cmake_minimum_required (VERSION 3.20)

project("etaHEN-SDK")

set(PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_ROOT}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_ROOT}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_ROOT}/lib)	# static libs are archive

include_directories	(SYSTEM "${PROJECT_ROOT}/include")
include_directories(SYSTEM "${D_PS5SDK}")
include_directories(SYSTEM "${D_PS5SDK}/include")

add_subdirectory(libhijacker)
add_subdirectory(libNidResolver)
add_subdirectory(libelfloader)
add_subdirectory(ELF_samples/hwinfo)
add_subdirectory(ELF_samples/tcp_echo_server)
add_subdirectory(ELF_samples/klog_printf)
add_subdirectory(ELF_samples/http2)
add_subdirectory(ELF_samples/list_files)

add_subdirectory(Plugin_samples/utility_daemon)
add_subdirectory(Plugin_samples/Illusion_cheats)
add_subdirectory(Plugin_samples/PS5Debug)
