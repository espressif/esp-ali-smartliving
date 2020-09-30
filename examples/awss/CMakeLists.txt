
# (Automatically converted from project Makefile by convert_to_cmake.py.)

# The following lines of boilerplate have to be in your project's CMakeLists
# in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.5)

set(__PROJECT_GROUP_LINK_COMPONENTS 1)

set(EXTRA_COMPONENT_DIRS "../..")

if(NOT DEFINED IDF_TARGET)
    set(IDF_TARGET "esp32")
endif()

set(SDKCONFIG_DEFAULTS ${CMAKE_CURRENT_LIST_DIR}/sdkconfig_defaults/sdkconfig.defaults.${IDF_TARGET})

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(awss)
