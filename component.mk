# Makefile
COMPONENT_ADD_LDFLAGS += -u ota_pubn_buf
COMPONENT_PRIV_INCLUDEDIRS := \
ali-smartliving-device-sdk-c/output/release/include/imports

COMPONENT_ADD_INCLUDEDIRS := \
conn_mgr \
ali-smartliving-device-sdk-c/output/release/include \
ali-smartliving-device-sdk-c/output/release/include/exports

COMPONENT_SRCDIRS := \
conn_mgr \
wrappers

CFLAGS += -Wno-char-subscripts

LIBS += iot_sdk
COMPONENT_ADD_LDFLAGS += -L $(COMPONENT_PATH)/ali-smartliving-device-sdk-c/output/release/lib $(addprefix -l,$(LIBS))
