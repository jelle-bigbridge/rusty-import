#!/usr/bin/env bash

cargo build --release
cross build --target x86_64-unknown-linux-musl --release

mkdir -p install
cp ./target/release/rusty-import install/rusty-import
cp ./target/x86_64-unknown-linux-musl/release/rusty-import install/static-rusty-import
