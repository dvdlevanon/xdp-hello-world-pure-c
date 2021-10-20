#!/bin/bash

make || exit 1

echo "===="
echo "Run sudo cat /sys/kernel/debug/tracing/trace_pipe to see output"
echo "===="

# On most standard kernel, bpf programs must be loaded as a root user
#
sudo ./xdp_loader
