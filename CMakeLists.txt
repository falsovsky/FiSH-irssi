CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

PROJECT(FiSH-irssi C)

SET(VERSION_MAJOR 1)
SET(VERSION_MINOR 4)

SET(FISH_VERSION ${VERSION_MAJOR}.${VERSION_MINOR})

INCLUDE (CheckIncludeFiles)

# Look for some headers
CHECK_INCLUDE_FILES(stdint.h HAVE_STDINT)
if(NOT DEFINED HAVE_STDINT)
    # SunOS 5.8 doesnt have stdint.h but inttypes.h can replace it
    CHECK_INCLUDE_FILES(inttypes.h HAVE_INTTYPES)
endif()

# Look for pkg-config
FIND_PACKAGE(PkgConfig REQUIRED)

# Look for glib2
PKG_CHECK_MODULES(GLIB_PKG REQUIRED glib-2.0)
if(GLIB_PKG_FOUND)
    INCLUDE_DIRECTORIES(${GLIB_PKG_INCLUDE_DIRS})
    LINK_DIRECTORIES(${GLIB_PKG_LIBRARY_DIRS})
    MESSAGE(STATUS "Using glib-2.0 ${GLIB_PKG_VERSION}")
ENDIF()

# Look for OpenSSL
PKG_CHECK_MODULES(OPENSSL REQUIRED openssl)
if(OPENSSL_FOUND)
    INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIRS})
    LINK_DIRECTORIES(${OPENSSL_LIBRARY_DIRS})
    MESSAGE(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
ENDIF()

# Sets a variable that the user can set with 
# cmake -DIRSSI_INCLUDE_DIR:PATH=/path/to/irssi/includes .
SET(IRSSI_INCLUDE_DIR "" CACHE PATH "Path to irssi include files")

# Tries to find the irssi include files in the most common places,
# and in the user defined directory
FIND_PATH(IRSSI_INCLUDE_PATH
    NAMES irssi-config.h src/common.h
    PATHS /usr/include/irssi /usr/local/include/irssi ${IRSSI_INCLUDE_DIR}
)

# Bail out if the required irssi files werent found
IF(NOT IRSSI_INCLUDE_PATH)
    MESSAGE(SEND_ERROR "Could not detect the irssi include files. Please run:\n# cmake -DIRSSI_INCLUDE_DIR:PATH=/path/to/irssi/includes .")
    RETURN()
ENDIF()

MESSAGE(STATUS "irssi includes were found on ${IRSSI_INCLUDE_PATH}")

# Add the weirdo irssi includes directories
INCLUDE_DIRECTORIES(${IRSSI_INCLUDE_PATH} ${IRSSI_INCLUDE_PATH}/src ${IRSSI_INCLUDE_PATH}/src/fe-common/core ${IRSSI_INCLUDE_PATH}/src/core)

MESSAGE(STATUS "The module will be installed by default to ${CMAKE_INSTALL_PREFIX}/lib/irssi/modules")
MESSAGE(STATUS "You can change it with 'cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr .'")

# Generate a version based on the git version
IF(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/.git)
    FIND_PACKAGE(Git)
    IF(GIT_FOUND)
        EXECUTE_PROCESS(
            COMMAND ${GIT_EXECUTABLE} rev-list --count HEAD
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            OUTPUT_VARIABLE "FISH_GIT_REVISION"
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE)
        EXECUTE_PROCESS(
            COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            OUTPUT_VARIABLE "FISH_GIT_HASH"
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE)
        SET(FISH_VERSION r${FISH_GIT_REVISION}-${FISH_GIT_HASH})
    ENDIF(GIT_FOUND)
ENDIF(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/.git)

ADD_SUBDIRECTORY(src)

INSTALL(FILES README.md FiSH-irssi.txt DESTINATION share/doc/FiSH-irssi)