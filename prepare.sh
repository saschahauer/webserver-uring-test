#!/usr/bin/env bash

mkdir -p build
pushd build && meson setup && meson compile
popd

openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl req -new -x509 -key key.pem -out cert.pem -days 360
mkdir -p public
dd if=/dev/urandom of=public/foo bs=1024 count=1024
