cmake_minimum_required(VERSION 2.6)

project (FiSH-irssi C)

find_package(PkgConfig REQUIRED)

pkg_check_modules(GLIB_PKG REQUIRED glib-2.0)
pkg_check_modules(OPENSSL REQUIRED openssl)

if(GLIB_PKG_FOUND)
    include_directories(${GLIB_PKG_INCLUDE_DIRS})
    message(STATUS "Using glib-2.0 ${GLIB_PKG_VERSION}")
endif()

if(OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIRS})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
endif()

set(IRSSI_PATH "/usr/include/irssi" PATH "path to irssi include files")

# Find irssi Include dir
find_path(irssi_INCLUDE_DIR
  NAMES irssi-config.h src/common.h
  PATHS ${IRSSI_PATH} /usr/local/include/irssi
)

if(NOT irssi_INCLUDE_DIR)
  message(SEND_ERROR "Could not auto find the irssi include files, please run:\n# cmake -D IRSSI_PATH=/path/to/irssi/includes .")
  return()
endif()

include_directories(${irssi_INCLUDE_DIR} ${irssi_INCLUDE_DIR}/src ${irssi_INCLUDE_DIR}/src/fe-common/core ${irssi_INCLUDE_DIR}/src/core)

add_subdirectory (src)
