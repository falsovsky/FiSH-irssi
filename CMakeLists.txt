cmake_minimum_required (VERSION 2.8.11)
project (FiSH-irssi)

find_package(PkgConfig REQUIRED)

pkg_check_modules(GLIB_PKG REQUIRED glib-2.0)
pkg_search_module(OPENSSL REQUIRED openssl)

if(GLIB_PKG_FOUND)
    include_directories(${GLIB_PKG_INCLUDE_DIRS})
    message(STATUS "Using glib-2.0 ${GLIB_PKG_VERSION}")
endif()


if(OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIRS})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
endif()

# configure a header file to pass some of the CMake settings
# to the source code
#configure_file (
#  "${PROJECT_SOURCE_DIR}/src/config.h.in"
#  "${PROJECT_BINARY_DIR}/src/config.h"
#  )

set(IRSSI_INCLUDES "/usr/include/irssi" CACHE PATH "path to irssi include files")

# Include dir
find_path(irssi_INCLUDE_DIR
  NAMES irssi-config.h src/common.h
  PATHS ${IRSSI_INCLUDES}
)

include_directories(${irssi_INCLUDE_DIR} ${irssi_INCLUDE_DIR}/src ${irssi_INCLUDE_DIR}/src/fe-common/core ${irssi_INCLUDE_DIR}/src/core)

add_subdirectory (src)
