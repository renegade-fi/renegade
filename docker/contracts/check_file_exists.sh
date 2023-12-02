#!/bin/bash

# Exits successfully if the passed-in file exists

# Check if enough arguments are passed
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <signal_file_path>"
    exit 1
fi

# The first argument is the path to the signal file
SIGNAL_FILE="$1"

if [ ! -f "$SIGNAL_FILE" ]; then
    exit 1
fi

exit 0
