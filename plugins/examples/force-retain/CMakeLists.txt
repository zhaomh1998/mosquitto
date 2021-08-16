add_library(mosquitto_force_retain MODULE
	mosquitto_force_retain.c
)

target_include_directories(mosquitto_force_retain PRIVATE
	"${OPENSSL_INCLUDE_DIR}"
	"${STDBOOL_H_PATH}"
	"${STDINT_H_PATH}"
	"${mosquitto_SOURCE_DIR}"
	"${mosquitto_SOURCE_DIR}/include"
)

link_directories(${mosquitto_SOURCE_DIR})

set_target_properties(mosquitto_force_retain PROPERTIES
	PREFIX ""
	POSITION_INDEPENDENT_CODE 1
)
if(WIN32)
	target_link_libraries(mosquitto_force_retain mosquitto)
endif()

# Don't install, these are example plugins only.
#install(TARGETS mosquitto_force_retain RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
