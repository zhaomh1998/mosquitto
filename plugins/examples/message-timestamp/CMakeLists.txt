add_library(mosquitto_message_timestamp MODULE
	mosquitto_message_timestamp.c
)

target_include_directories(mosquitto_message_timestamp PRIVATE
	"${OPENSSL_INCLUDE_DIR}"
	"${STDBOOL_H_PATH}"
	"${STDINT_H_PATH}"
	"${mosquitto_SOURCE_DIR}"
	"${mosquitto_SOURCE_DIR}/include"
)

set_target_properties(mosquitto_message_timestamp PROPERTIES
	PREFIX ""
	POSITION_INDEPENDENT_CODE 1
)

# Don't install, these are example plugins only.
#install(TARGETS mosquitto_message_timestamp RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
