add_library (fish MODULE base64.c blowfish.c inifile.c DH1080.c FiSH.c password.c)
target_link_libraries ( fish crypto glib-2.0 )

install (TARGETS fish LIBRARY DESTINATION lib/irssi/modules)
