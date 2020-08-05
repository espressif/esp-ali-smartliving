INCLUDE_DIRECTORIES (${PROJECT_SOURCE_DIR})
INCLUDE_DIRECTORIES (${PROJECT_SOURCE_DIR}/include)
INCLUDE_DIRECTORIES (${PROJECT_SOURCE_DIR}/include/exports)
INCLUDE_DIRECTORIES (${PROJECT_SOURCE_DIR}/include/imports)
INCLUDE_DIRECTORIES (${PROJECT_SOURCE_DIR}/components/timer_service/)

FILE (GLOB src_services_timer_service_SRCS
    ${PROJECT_SOURCE_DIR}/components/timer_service/*.c
)

ADD_LIBRARY (iot_timer_service OBJECT
    ${src_services_timer_service_SRCS}
)

