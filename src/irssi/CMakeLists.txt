CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/FiSH_version.h.in ${CMAKE_CURRENT_SOURCE_DIR}/FiSH_version.h)

ADD_LIBRARY(fish MODULE FiSH.c)

TARGET_LINK_LIBRARIES(fish crypto glib-2.0 common)
target_include_directories(fish PUBLIC ../common)

if (APPLE)
	SET_TARGET_PROPERTIES(fish PROPERTIES LINK_FLAGS "-undefined dynamic_lookup")
endif()

INSTALL(TARGETS fish LIBRARY DESTINATION lib/irssi/modules)
