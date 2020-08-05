DEPENDS             := src/ref-impl/hal
DEPENDS             += src/ref-impl/tls

HDR_REFS            += src/infra
HDR_REFS            += src/services
HDR_REFS            += linkkit/gateway
HDR_REFS            += linkkit/certification
HDR_REFS            += linkkit/living_platform
HDR_REFS            += linkkit/living_platform_rawdata

LDFLAGS             := -Bstatic
LDFLAGS             += -liot_sdk

LDFLAGS             += -liot_hal
CFLAGS              := $(filter-out -ansi,$(CFLAGS))
ifneq (,$(filter -D_PLATFORM_IS_WINDOWS_,$(CFLAGS)))
LDFLAGS             += -lws2_32
CFLAGS              := $(filter-out -DCOAP_COMM_ENABLED,$(CFLAGS))
endif
ifneq (,$(filter -DSUPPORT_ITLS,$(CFLAGS)))
LDFLAGS             += -litls
else
LDFLAGS             += -liot_tls
endif

ifneq (,$(filter -D_PLATFORM_IS_LINUX_, $(CFLAGS)))
LDFLAGS += -L$(TOP_DIR)/lib/linux
LDFLAGS += -lawss_security
endif

SRCS_gateway                    := cJSON.c linkkit/gateway/gateway_entry.c \
                                    linkkit/gateway/gateway_main.c \
                                    linkkit/gateway/gateway_api.c \
                                    linkkit/gateway/gateway_ut.c
                      
SRCS_certification              := cJSON.c linkkit/certification/ct_entry.c \
                                    linkkit/certification/ct_main.c \
                                    linkkit/certification/ct_ut.c \
                                    linkkit/certification/ct_ota.c

SRCS_living_platform            := cJSON.c linkkit/living_platform/app_entry.c \
                                    linkkit/living_platform/living_platform_main.c \
                                    linkkit/living_platform/living_platform_ut.c

SRCS_living_platform_rawdata    := cJSON.c linkkit/living_platform_rawdata/app_entry.c \
                                    linkkit/living_platform_rawdata/living_platform_rawdata_main.c \
                                    linkkit/living_platform_rawdata/living_platform_rawdata_ut.c

# Syntax of Append_Conditional
# ---
#
# $(call Append_Conditional, TARGET, \  <-- Operated Variable
#   member1 member2 ...            , \  <-- Appended Members
#   switch1 switch2 ...            , \  <-- All These Switches are Defined
#   switch3 switch4 ...)                <-- All These Switches are Not Defined (Optional)

$(call Append_Conditional, LDFLAGS, \
    -litls \
    -lid2client \
    -lkm \
    -lplat_gen \
    -lalicrypto \
    -lmbedcrypto \
, \
SUPPORT_ITLS, \
SUPPORT_TLS)

$(call Append_Conditional, TARGET, gateway,             DEVICE_MODEL_ENABLED  DEVICE_MODEL_GATEWAY)
$(call Append_Conditional, TARGET, certification,       DEVICE_MODEL_ENABLED)
$(call Append_Conditional, TARGET, living_platform,     DEVICE_MODEL_ENABLED, DEVICE_MODEL_RAWDATA_SOLO)
$(call Append_Conditional, TARGET, living_platform_rawdata,     DEVICE_MODEL_ENABLED DEVICE_MODEL_RAWDATA_SOLO)

# Clear All Above when Build for Windows
#
ifneq (,$(filter -D_PLATFORM_IS_WINDOWS_,$(CFLAGS)))
    TARGET := living_platform
endif
