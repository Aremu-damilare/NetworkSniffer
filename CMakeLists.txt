cmake_minimum_required(VERSION 3.16)

# Project name
project(NetworkSniffer LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Qt6 Widgets
find_package(Qt6 REQUIRED COMPONENTS Core Widgets Gui)

# Find Qt UI Compiler (uic) for `.ui` files
qt_standard_project_setup()

# Specify the Npcap SDK root directory (Change path to your installed Npcap SDK location)
set(PCAP_ROOT "C:/Npcap-SDK")  # Ensure this path is correct

# Include directories for Pcap
include_directories(${PCAP_ROOT}/Include)

# Link Pcap libraries
set(PCAP_LIBRARIES
    ${PCAP_ROOT}/Lib/x64/Packet.lib
    ${PCAP_ROOT}/Lib/x64/wpcap.lib
)

# Add UI file
set(UI_FILES mainwindow.ui)
set(SRC_FILES main.cpp mainwindow.cpp)
set(H_FILES mainwindow.h)

qt_add_executable(NetworkSniffer
    ${SRC_FILES}
    ${H_FILES}
    ${UI_FILES}
)

# Link against Qt, Pcap, and Winsock
target_link_libraries(NetworkSniffer PRIVATE Qt6::Widgets Qt6::Gui Qt6::Core ${PCAP_LIBRARIES} ws2_32)
