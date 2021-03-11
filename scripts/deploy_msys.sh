#!/usr/bin/env sh

DIST=dist/win_x64
BUILD_DIR=build-msys

mkdir -p $DIST
mkdir -p $BUILD_DIR

cd $BUILD_DIR || exit
cmake -G "MSYS Makefiles" -D CMAKE_BUILD_TYPE=Release ..
cmake --build . -j$(($(nproc)*3/4))

cp $BUILD_DIR/rbc_validator $DIST
cp /mingw64/bin/libgomp-1.dll $DIST
cp /mingw64/bin/libwinpthread-1.dll $DIST
cp /mingw64/bin/libgcc_s_seh-1.dll $DIST
cp /mingw64/bin/libgmp-10.dll $DIST