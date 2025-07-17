#!/bin/bash

SDK_PATH="/home/kona/Linux/lvgl/SDK_LVGL_MINIP/host/"

export PATH="${SDK_PATH}/bin:${PATH}"

export SYSROOT="${SDK_PATH}/arm-buildroot-linux-gnueabi/sysroot"

export CROSS_COMPILE="arm-none-linux-gnueabi-"

export CC="${CROSS_COMPILE}gcc"
export CXX="${CROSS_COMPILE}g++"
export LD="${CROSS_COMPILE}ld"
export AR="${CROSS_COMPILE}ar"
export AS="${CROSS_COMPILE}as"

export CFLAGS="--sysroot=${SYSROOT}"
export LDFLAGS="--sysroot=${SYSROOT}"
