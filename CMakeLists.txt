set(lib_path ${CMAKE_CURRENT_SOURCE_DIR}/ali-smartliving-device-sdk-c/output/release/lib ${CMAKE_CURRENT_SOURCE_DIR}/ali-smartliving-device-sdk-c/lib/xtensa)

set(COMPONENT_PRIV_INCLUDEDIRS
    ali-smartliving-device-sdk-c/output/release/include/imports)
    
set(COMPONENT_ADD_INCLUDEDIRS
    conn_mgr
    ali-smartliving-device-sdk-c/output/release/include
    ali-smartliving-device-sdk-c/output/release/include/exports)

# Edit following two lines to set component requirements (see docs)
set(COMPONENT_REQUIRES "nvs_flash" "app_update" "esp-tls")
set(COMPONENT_PRIV_REQUIRES )

set(COMPONENT_SRCDIRS
    conn_mgr
    wrappers)

register_component()
component_compile_options(-DAUTH_MODE_CERT)

target_link_libraries(${COMPONENT_TARGET} "-L ${lib_path}")
target_link_libraries(${COMPONENT_TARGET} iot_sdk awss_security)
