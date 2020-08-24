set(COMPONENT_ADD_INCLUDEDIRS .)

set(COMPONENT_SRCS "transport_uart.c")

set(COMPONENT_REQUIRES "esp-ali-smartliving")
set(COMPONENT_PRIV_REQUIRES "databases")
register_component()