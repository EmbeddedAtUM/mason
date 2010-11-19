#!/bin/bash

export KERNEL_DIR=/usr/src/linux
export ARCH=x86_64
export CROSS_COMPILE=

if [ ! -n "${1+1}" ]; then
    NUMPROC=1
else
    NUMPROC=$1
fi

nice make -j$NUMPROC
