cmake_minimum_required(VERSION 3.10)

project(TCPDump VERSION 1.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)




# add the executable libpcap.a
add_executable(TCPDump main.cpp)
target_link_libraries(TCPDump PUBLIC pcap)