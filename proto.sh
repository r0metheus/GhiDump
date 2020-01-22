#!/bin/bash

SRC_DIR=$(pwd)/proto
DST_DIR=$(pwd)/src
DST_DIR_PY=$(pwd)/reader

protoc -I=$SRC_DIR --java_out=$DST_DIR $SRC_DIR/*
protoc -I=$SRC_DIR --python_out=$DST_DIR_PY $SRC_DIR/*
