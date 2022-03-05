cmake_minimum_required(VERSION 3.5)

project(hw_passwd LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(${PROJECT_NAME} hw_passwd.cpp rev_hw.cpp)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
  target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)
endif(OPENSSL_FOUND)
