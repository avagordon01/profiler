#!/usr/bin/env bash
set -euo pipefail

flocking_bin="$(ls -t /run/user/1000/hadeanos-binary-cache-1000/* | head -1)"
sudo ./main.py "${flocking_bin}" worker_impl.hh 552

#in aether, do ./run.sh
