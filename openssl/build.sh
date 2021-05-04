#! /bin/bash

VER=3
SRC_PFX=openssl-3.0.0-alpha15

if [ $1 == "a32" ]
then
PPATH=`pwd`;
cd $SRC_PFX-a32;
./Configure \
--prefix=$PPATH/$VER/openssl-a32 \
--cross-compile-prefix=arm-linux-gnueabihf- \
--release \
-static \
no-asm \
no-shared \
no-zlib-dynamic \
no-engine \
no-hw \
linux-armv4;
make;
make test;
make depend;
make install;
fi

if [ $1 == "x32" ]
then
PPATH=`pwd`;
cd $SRC_PFX-x32;
CPATH=`pwd`;
./config \
--openssldir=$CPATH \
--prefix=$PPATH/$VER/openssl-x32 \
--release \
-m32 \
no-asm \
no-shared \
no-zlib-dynamic;
make;
make test;
make depend;
make install;
fi

if [ $1 == "x64" ]
then
PPATH=`pwd`;
cd $SRC_PFX-x64;
CPATH=`pwd`;
./config \
--openssldir=$CPATH \
--prefix=$PPATH/$VER/openssl-x64 \
--release \
-m64 \
no-asm \
no-shared \
no-zlib-dynamic;
make;
make test;
make depend;
make install;
fi
