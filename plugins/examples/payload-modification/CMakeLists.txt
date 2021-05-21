add_library(mosquitto_payload_modification MODULE
	mosquitto_payload_modification.c
)

target_include_directories(mosquitto_payload_modification PRIVATE
	"${OPENSSL_INCLUDE_DIR}"
	"${STDBOOL_H_PATH}"
	"${STDINT_H_PATH}"
	"${mosquitto_SOURCE_DIR}"
	"${mosquitto_SOURCE_DIR}/include"
)

link_directories(${mosquitto_SOURCE_DIR})

set_target_properties(mosquitto_payload_modification PROPERTIES
	PREFIX ""
	POSITION_INDEPENDENT_CODE 1
)
if(WIN32)
	target_link_libraries(mosquitto_payload_modification mosquitto)
endif()

# Don't install, these are example plugins only.
#install(TARGETS mosquitto_payload_modification RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
