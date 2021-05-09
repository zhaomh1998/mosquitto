add_library(mosquitto_client_properties SHARED
	mosquitto_client_properties.c
)

target_include_directories(mosquitto_client_properties PRIVATE
	"${STDBOOL_H_PATH}"
	"${STDINT_H_PATH}"
	"${mosquitto_SOURCE_DIR}"
	"${mosquitto_SOURCE_DIR}/include"
)

link_directories(${mosquitto_SOURCE_DIR})

set_target_properties(mosquitto_client_properties PROPERTIES
	PREFIX ""
	POSITION_INDEPENDENT_CODE 1
)

if(WIN32)
	target_link_libraries(mosquitto_client_properties mosquitto)
endif()

# Don't install, these are example plugins only.
#install(TARGETS mosquitto_client_properties RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
