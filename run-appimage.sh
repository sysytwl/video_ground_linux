#!/usr/bin/env sh
set -eu

HERE="$(dirname "$(readlink -f "$0")")"
APPIMAGE_EXTRACT_AND_RUN=1 exec "${HERE}/WiFiVideoReceiver-x86_64.AppImage" "$@"