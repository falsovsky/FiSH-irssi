add_executable(test1 test1.c)
TARGET_LINK_LIBRARIES(test1 common)
target_include_directories(test1 PUBLIC ../common)
target_include_directories(test1 PUBLIC ../irssi)

if (APPLE)
	SET_TARGET_PROPERTIES(test1 PROPERTIES LINK_FLAGS "-undefined dynamic_lookup")
endif()
