cmake_minimum_required(VERSION 3.5)

set(SOURCES "sip.c" "alaw.c")
set(RECS)

# Add extra dependancies

idf_component_register(
			SRCS ${SOURCES}
			INCLUDE_DIRS "include"
			REQUIRES ${RECS}
			EMBED_FILES "../../build/partition_table/partition-table.bin"
)

add_definitions(-DBUILD_ESP32_USING_CMAKE)
set_property(SOURCE "../../build/partition_table/partition-table.bin" PROPERTY GENERATED 1)

