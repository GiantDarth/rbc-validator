#!/usr/bin/env sh

DIST=dist/win_x64
BUILD_DIR=build-msys

rm -r $BUILD_DIR

mkdir -p $DIST
mkdir -p $BUILD_DIR

cmake -G "MSYS Makefiles" -D CMAKE_BUILD_TYPE=Release -S . -B $BUILD_DIR
cmake --build $BUILD_DIR -j$(($(nproc)*3/4))

cp $BUILD_DIR/rbc_validator $DIST
cp /mingw64/bin/libgomp-1.dll $DIST
cp /mingw64/bin/libwinpthread-1.dll $DIST
cp /mingw64/bin/libgcc_s_seh-1.dll $DIST
cp /mingw64/bin/libgmp-10.dll $DIST
cp /mingw64/bin/libcrypto-1_1-x64.dll $DIST