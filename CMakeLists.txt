cmake_minimum_required(VERSION 3.10)

# 프로젝트 이름과 버전 설정
project(IBE_AET VERSION 1.0)

# C++ 표준 설정
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 필요한 라이브러리 패키지 찾기
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# PBC 라이브러리와 관련된 include 경로 및 라이브러리 설정
include_directories(/usr/local/include/pbc)
set(GMP_LIBRARY "-lgmp")
set(PBC_LIBRARY "-lpbc")

# 실행 파일 출력 경로 설정
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

# 소스 파일과 헤더 파일 경로 설정
include_directories(${CMAKE_SOURCE_DIR}/include)

# MIBEAET 실행 파일 생성
set(MIBEAET_SOURCES src/MIBEAET.cpp)
set(IBEAET_SOURCES src/IBEAET.cpp)

add_executable(MIBEAET ${MIBEAET_SOURCES})
add_executable(IBEAET ${IBEAET_SOURCES})

target_link_libraries(MIBEAET ${PBC_LIBRARY} ${GMP_LIBRARY} ${OPENSSL_LIBRARIES} -lcrypto)
target_link_libraries(IBEAET ${PBC_LIBRARY} ${GMP_LIBRARY} ${OPENSSL_LIBRARIES} -lcrypto)
