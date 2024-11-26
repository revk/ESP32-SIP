cmake_minimum_required(VERSION 3.5...3.25)

set(SOURCES "sip.c" "sipsin.c" "alaw.c" "siptools.c")
set(RECS esp_timer)

# Add extra dependencies

idf_component_register(
			SRCS ${SOURCES}
			INCLUDE_DIRS "include"
			REQUIRES ${RECS}
)

add_definitions(-DBUILD_ESP32_USING_CMAKE)
