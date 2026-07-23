#!/bin/sh
# If this script is ever run, it drops a sentinel file next to itself.
touch "$(dirname "$0")/SENTINEL_EXECUTED_SH"
