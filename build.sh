#!/usr/bin/env bash

set -e
set -u

smartliving_path="ali-smartliving-device-sdk-c"
ali_make="make -C"
example_solo_path="examples/solo/example_solo"
example_light_path="examples/solutions/smart_light"

echo "Please follow below steps to configure chips to generate specific bin(s)"
while :; do
echo "STEP 1: Choose chip (0=esp8266, 1=esp32, 2=esp32s2)"
read input

if [ $input == 0 ]; then
    chip="esp8266"
    num=3
    app_make="make -C"
    break
elif [ $input == 1 ]; then
    chip="esp32"
    num=1
    app_make="idf.py -C"
    break
elif [ $input == 2 ]; then
    chip="esp32s2"
    num=2
    app_make="idf.py -C"
    break
else
    echo "Only support 0-2, Please Input again!!!"
fi
done

while :; do
echo "STEP 2: Need configure ali-smartliving-device-sdk"
echo "        0 = no need build (already builded)"
echo "        1 = clean and choose chip to build"
echo "        2 = clean and choose chip and make menuconfig to build"
read input

if [ $input == 0 ]; then
    break;
elif [ $input == 1 ]; then
    $ali_make $smartliving_path distclean
    echo $num | $ali_make $smartliving_path reconfig
    $ali_make $smartliving_path
    break
elif [ $input == 2 ]; then
    $ali_make $smartliving_path distclean
    echo $num | $ali_make $smartliving_path reconfig
    $ali_make $smartliving_path menuconfig
    $ali_make $smartliving_path
    break
else
    echo "Only support 0-2, Please Input again!!!"
fi
done

while :; do
echo "STEP 3: Choose example app to build"
echo "        0 = example_solo(recommend)"
echo "        1 = smart_light(recommend)"
read input

if [ $input == 0 ]; then
    app_path=$example_solo_path
    break
elif [ $input == 1 ]; then
    app_path=$example_light_path
    break
else
    echo "Only support 0-1, Please Input again!!!"
fi
done

build_function(){
    echo "Build $app_path by chip $chip..."

    if [ $chip == "esp8266" ]; then
        $app_make $app_path clean
        $app_make $app_path defconfig
        action=""
    else
        $app_make $app_path fullclean
        $app_make $app_path set-target $chip
        action="build"
    fi

    if [ $1 == 1 ]; then
        $app_make $app_path menuconfig
    fi

    $app_make $app_path $action
        
}

while :; do
echo "STEP 4: Need configure app"
echo "        0 = no menuconfig and build"
echo "        1 = menuconfig and build"
read input

if [ $input == 0 ]; then
    build_function 0
    break
elif [ $input == 1 ]; then
    build_function 1
    break
else
    echo "Only support 0-1, Please Input again!!!"
fi
done

echo "Now build all bin successfully!!!"
echo "You can 'cd $app_path' and execute 'make flash monitor'(if esp8266) or 'idf.py flash monitor'(if esp32 or esp32s2) to run your example"