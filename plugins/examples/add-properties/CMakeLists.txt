include_directories(${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/include
			${STDBOOL_H_PATH} ${STDINT_H_PATH})

add_library(mosquitto_add_properties SHARED mosquitto_add_properties.c)
set_target_properties(mosquitto_add_properties PROPERTIES
	POSITION_INDEPENDENT_CODE 1
)
set_target_properties(mosquitto_add_properties PROPERTIES PREFIX "")

# Don't install, these are example plugins only.
#install(TARGETS mosquitto_add_properties RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
