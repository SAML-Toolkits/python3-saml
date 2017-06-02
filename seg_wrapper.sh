#!/bin/bash
ulimit -c unlimited
"$@"
if [[ $? -eq 139 ]]; then
    gdb -q $1 core -x ./backtrace
fi
