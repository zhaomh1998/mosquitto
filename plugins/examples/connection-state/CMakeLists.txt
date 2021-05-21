add_library(mosquitto_connection_state MODULE
	mosquitto_connection_state.c
)

target_include_directories(mosquitto_connection_state PRIVATE
	"${STDBOOL_H_PATH}"
	"${STDINT_H_PATH}"
	"${mosquitto_SOURCE_DIR}"
	"${mosquitto_SOURCE_DIR}/include"
)

set_target_properties(mosquitto_connection_state PROPERTIES
	PREFIX ""
	POSITION_INDEPENDENT_CODE 1
)

# Don't install, these are example plugins only.
#install(TARGETS mosquitto_connection_state RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
