NAME := libiot_dev_diagnosis

$(NAME)_MBINS_TYPE := kernel
$(NAME)_VERSION := 2.3.0
$(NAME)_SUMMARY := used for device remote diagnosis

$(NAME)_COMPONENTS += framework/bluetooth/breeze

$(NAME)_INCLUDES += . 
$(NAME)_INCLUDES += ../../../../../../../bluetooth/breeze/api/
$(NAME)_SOURCES :=
$(NAME)_SOURCES += dev_diagnosis.c dev_errcode.c dev_state_machine.c dev_offline_ota.c

$(NAME)_SOURCES += diagnosis_offline_log.c

ifeq ($(COMPILER),)
else ifeq ($(COMPILER),gcc)
$(NAME)_CFLAGS  += -Wall -Werror -Wno-unused-variable -Wno-unused-parameter -Wno-implicit-function-declaration
$(NAME)_CFLAGS  += -Wno-type-limits -Wno-sign-compare -Wno-pointer-sign -Wno-uninitialized
$(NAME)_CFLAGS  += -Wno-return-type -Wno-unused-function -Wno-unused-but-set-variable
$(NAME)_CFLAGS  += -Wno-unused-value -Wno-strict-aliasing
endif
