#! /bin/sh
TARGET_LIB=/home/kona/Linux/lvgl/SDK_LVGL_MINIP/target/usr/lib
if [ -d "./build" ]
then
    echo "Directory ./build exists."
else
    echo "Directory ./build does not exists. create build directory"
    mkdir build
fi
  cd build
  cmake  -DCMAKE_TOOLCHAIN_FILE=../toolchain.arm.cmake -DCMAKE_BUILD_TYPE=Release ../
  make
  echo "TARGET_LIB = $TARGET_LIB"
  cp KSS_SDK_Linux ../
  cd ..
  cd build/ksssdk
  cp libksssdk.a ../../
  cd ../..
  rm -rf build
