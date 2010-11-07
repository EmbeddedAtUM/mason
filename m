#!/bin/bash

pushd ../..
source ./android.env
popd

if [ ! -n "${1+1}" ]; then
    NUMPROC=1
else
    NUMPROC=$1
fi

nice make -j$NUMPROC
