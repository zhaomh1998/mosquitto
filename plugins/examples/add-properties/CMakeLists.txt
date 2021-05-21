add_library(mosquitto_add_properties MODULE
	mosquitto_add_properties.c
)

target_include_directories(mosquitto_add_properties PRIVATE
	"${STDBOOL_H_PATH}"
	"${STDINT_H_PATH}"
	"${mosquitto_SOURCE_DIR}"
	"${mosquitto_SOURCE_DIR}/include"
)

set_target_properties(mosquitto_add_properties PROPERTIES
	PREFIX ""
	POSITION_INDEPENDENT_CODE 1
)

# Don't install, these are example plugins only.
#install(TARGETS mosquitto_add_properties RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
