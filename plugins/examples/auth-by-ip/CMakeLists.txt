add_library(mosquitto_auth_by_ip MODULE
	mosquitto_auth_by_ip.c
)

target_include_directories(mosquitto_auth_by_ip PRIVATE
	"${OPENSSL_INCLUDE_DIR}"
	"${STDBOOL_H_PATH} ${STDINT_H_PATH}"
	"${mosquitto_SOURCE_DIR}"
	"${mosquitto_SOURCE_DIR}/include"
)

set_target_properties(mosquitto_auth_by_ip PROPERTIES
	PREFIX ""
	POSITION_INDEPENDENT_CODE 1
)

if(WIN32)
	target_link_libraries(mosquitto_auth_by_ip mosquitto)
endif()

# Don't install, these are example plugins only.
#install(TARGETS mosquitto_auth_by_ip RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
