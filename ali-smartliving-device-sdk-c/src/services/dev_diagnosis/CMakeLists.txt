INCLUDE_DIRECTORIES (${PROJECT_SOURCE_DIR})
INCLUDE_DIRECTORIES (${PROJECT_SOURCE_DIR}/include)
INCLUDE_DIRECTORIES (${PROJECT_SOURCE_DIR}/include/exports)
INCLUDE_DIRECTORIES (${PROJECT_SOURCE_DIR}/include/imports)
INCLUDE_DIRECTORIES (${PROJECT_SOURCE_DIR}/src/services/dev_diagnosis/)

FILE (GLOB src_services_dev_diagnosis_SRCS
    ${PROJECT_SOURCE_DIR}/src/services/dev_diagnosis/*.c
)

ADD_LIBRARY (iot_dev_diagnosis OBJECT
    ${src_services_dev_diagnosis_SRCS}
)

