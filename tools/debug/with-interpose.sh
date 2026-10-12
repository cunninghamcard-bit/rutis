#!/bin/sh
# TEMPORARY (#287 debug): cargo's test runner; sets the interposer at the last
# hop, since macOS drops DYLD_* when a system binary (bash, sh) is exec'd.
DYLD_INSERT_LIBRARIES="$KILL_INTERPOSE" exec "$@"
