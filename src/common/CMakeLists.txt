ADD_LIBRARY(common STATIC base64.c blowfish.c inifile.c DH1080.c password.c)
set_property(TARGET common PROPERTY POSITION_INDEPENDENT_CODE TRUE)
TARGET_LINK_LIBRARIES(common crypto glib-2.0)
target_include_directories(common PUBLIC ../irssi)

if (APPLE)
	SET_TARGET_PROPERTIES(common PROPERTIES LINK_FLAGS "-undefined dynamic_lookup")
endif()
