cmake_minimum_required(VERSION 3.10)

project(IBEAET VERSION 1.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

include_directories(/usr/local/include/pbc)
set(GMP_LIBRARY "-lgmp")
set(PBC_LIBRARY "-lpbc")

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable(frontend
    src/main.cpp
    src/IBEAET.cpp
    src/EZE20.cpp
)

target_link_libraries(frontend
    ${PBC_LIBRARY}
    ${GMP_LIBRARY}
    ${OPENSSL_LIBRARIES}
    -lcrypto
)