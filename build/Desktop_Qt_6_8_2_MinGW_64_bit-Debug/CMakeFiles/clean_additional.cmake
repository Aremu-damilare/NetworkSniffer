# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Debug")
  file(REMOVE_RECURSE
  "CMakeFiles\\NetworkSniffer_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\NetworkSniffer_autogen.dir\\ParseCache.txt"
  "NetworkSniffer_autogen"
  )
endif()
