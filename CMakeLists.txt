cmake_minimum_required(VERSION 2.6)

project (FiSH-irssi C)

set(VERSION_MAJOR 1)
set(VERSION_MINOR 3)

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
find_path(irssi_INCLUDE_DIR
	NAMES irssi-config.h src/common.h
	PATHS ${IRSSI_PATH} /usr/local/include/irssi
	)

if(NOT irssi_INCLUDE_DIR)
	message(SEND_ERROR "Could not auto find the irssi include files, please run:\n# cmake -DIRSSI_PATH:PATH=/path/to/irssi/includes .")
	return()
endif()

include_directories(${irssi_INCLUDE_DIR} ${irssi_INCLUDE_DIR}/src ${irssi_INCLUDE_DIR}/src/fe-common/core ${irssi_INCLUDE_DIR}/src/core)

message(STATUS "The module will be installed to ${CMAKE_INSTALL_PREFIX}/lib/irssi/modules\nChange it with 'cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr .'")

add_subdirectory (src)

install(FILES doc/FiSH-irssi.txt DESTINATION share/doc/FiSH-irssi) 

set(CPACK_COMPONENTS_ALL_IN_ONE_PACKAGE 1)

IF(EXISTS "${CMAKE_ROOT}/Modules/CPack.cmake")
	INCLUDE(InstallRequiredSystemLibraries)

	SET(CPACK_SET_DESTDIR "on")
	SET(CPACK_PACKAGING_INSTALL_PREFIX "/tmp")
	SET(CPACK_GENERATOR "DEB;RPM")


	SET(CPACK_PACKAGE_DESCRIPTION "FiSH encryption for irssi")
	SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "FiSH encryption for irssi")
	SET(CPACK_PACKAGE_VENDOR "Pedro de Oliveira")
	SET(CPACK_PACKAGE_CONTACT "falsovsky@gmail.com")
	SET(CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}_${VERSION_MAJOR}.${VERSION_MINOR}")
	SET(CPACK_SOURCE_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}_${VERSION_MAJOR}.${VERSION_MINOR}")


	set(CPACK_COMPONENTS_ALL_IN_ONE_PACKAGE 1)

	SET(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.1.3), libssl1.0.0 (>= 1.0.0), libglib2.0-0 (>= 2.24.0), irssi (>= 0.8.13)")

	#SET(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
	SET(CPACK_DEBIAN_ARCHITECTURE ${CMAKE_SYSTEM_PROCESSOR})

	SET(CPACK_COMPONENTS_ALL Libraries ApplicationData)
	INCLUDE(CPack)

ENDIF(EXISTS "${CMAKE_ROOT}/Modules/CPack.cmake")
