#!/bin/bash

set -eu

cmake -H. -Bbuild
cd build
make
