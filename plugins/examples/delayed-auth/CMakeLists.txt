add_library(mosquitto_delayed_auth MODULE
	mosquitto_delayed_auth.c
)

target_include_directories(mosquitto_delayed_auth PRIVATE
	"${STDBOOL_H_PATH}"
	"${STDINT_H_PATH}"
	"${mosquitto_SOURCE_DIR}"
	"${mosquitto_SOURCE_DIR}/include"
)

if(WITH_BUNDLED_DEPS)
	target_include_directories(mosquitto_delayed_auth PRIVATE
		"${mosquitto_SOURCE_DIR}/deps"
	)
endif()

set_target_properties(mosquitto_delayed_auth PROPERTIES
	PREFIX ""
	POSITION_INDEPENDENT_CODE 1
)

# Don't install, these are example plugins only.
#install(TARGETS mosquitto_delayed_auth RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
