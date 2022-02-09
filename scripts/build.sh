#!/bin/bash

set -eu

build_dir="build-$(uname -s)"
cmake -H. -B"$build_dir"
cd "$build_dir"
make
