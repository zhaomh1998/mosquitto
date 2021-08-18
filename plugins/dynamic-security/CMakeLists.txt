if(CJSON_FOUND AND WITH_TLS)
	add_definitions("-DWITH_CJSON")

	set(CLIENT_INC
		"${CJSON_INCLUDE_DIRS}"
		"${OPENSSL_INCLUDE_DIR}"
		"${PTHREAD_INCLUDE_DIR}"
		"${STDBOOL_H_PATH}"
		"${STDINT_H_PATH}"
		"${mosquitto_SOURCE_DIR}"
		"${mosquitto_SOURCE_DIR}/deps"
		"${mosquitto_SOURCE_DIR}/include"
		"${mosquitto_SOURCE_DIR}/lib"
		"${mosquitto_SOURCE_DIR}/src"
	)

	set(CLIENT_DIR "${mosquitto_BINARY_DIR}/lib" "${CJSON_DIR}")

	add_library(mosquitto_dynamic_security MODULE
		acl.c
		auth.c
		clients.c
		clientlist.c
		config_init.c
		dynamic_security.h
		groups.c
		grouplist.c
		hash.c
		json_help.c
		json_help.h
		../../lib/misc_mosq.c ../../lib/misc_mosq.h
		../../src/password_mosq.c ../../src/password_mosq.h
		plugin.c
		roles.c
		rolelist.c
	)

	target_include_directories(mosquitto_dynamic_security PRIVATE
		${CLIENT_INC}
	)
	link_directories(${CLIENT_DIR} "${mosquitto_SOURCE_DIR}")

	set_target_properties(mosquitto_dynamic_security PROPERTIES
		PREFIX ""
		POSITION_INDEPENDENT_CODE 1
	)

	target_link_libraries(mosquitto_dynamic_security ${CJSON_LIBRARIES})
	if(WIN32)
		target_link_libraries(mosquitto_dynamic_security mosquitto)
	endif()

	install(TARGETS mosquitto_dynamic_security
		RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
		LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	)
endif()
