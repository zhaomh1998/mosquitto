include_directories(${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/include
			${STDBOOL_H_PATH} ${STDINT_H_PATH})

add_library(mosquitto_connection_state SHARED mosquitto_connection_state.c)
set_target_properties(mosquitto_connection_state PROPERTIES
	POSITION_INDEPENDENT_CODE 1
)
set_target_properties(mosquitto_connection_state PROPERTIES PREFIX "")

# Don't install, these are example plugins only.
#install(TARGETS mosquitto_connection_state RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
