#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPDIR="${ROOT_DIR}/build/AppDir"
OUTPUT="${ROOT_DIR}/WiFiVideoReceiver-x86_64.AppImage"

cmake -S "${ROOT_DIR}" -B "${ROOT_DIR}/build" -DCMAKE_BUILD_TYPE=Release
cmake --build "${ROOT_DIR}/build" --parallel

rm -rf "${APPDIR}"
install -Dm755 "${ROOT_DIR}/build/WiFiVideoReceiver" "${APPDIR}/usr/bin/WiFiVideoReceiver"
install -Dm755 "${ROOT_DIR}/packaging/appimage/AppRun" "${APPDIR}/AppRun"
install -Dm644 "${ROOT_DIR}/packaging/appimage/esp32-video-receiver.desktop" \
    "${APPDIR}/esp32-video-receiver.desktop"
install -Dm644 "${ROOT_DIR}/packaging/appimage/esp32-video-receiver.png" \
    "${APPDIR}/esp32-video-receiver.png"
install -Dm644 "${ROOT_DIR}/gs.ini" "${APPDIR}/usr/share/wifi-video-receiver/gs.ini"

if [[ -f /usr/share/fonts/TTF/DejaVuSans.ttf ]]; then
    install -Dm644 /usr/share/fonts/TTF/DejaVuSans.ttf \
        "${APPDIR}/usr/share/wifi-video-receiver/DejaVuSans.ttf"
elif [[ -f /usr/share/fonts/truetype/dejavu/DejaVuSans.ttf ]]; then
    install -Dm644 /usr/share/fonts/truetype/dejavu/DejaVuSans.ttf \
        "${APPDIR}/usr/share/wifi-video-receiver/DejaVuSans.ttf"
fi

APPIMAGE_EXTRACT_AND_RUN=1 NO_STRIP=1 \
    "${ROOT_DIR}/linuxdeploy-x86_64.AppImage" --appdir "${APPDIR}" \
    --executable "${APPDIR}/usr/bin/WiFiVideoReceiver" \
    --desktop-file "${APPDIR}/esp32-video-receiver.desktop" \
    --icon-file "${APPDIR}/esp32-video-receiver.png"

rm -f "${OUTPUT}"
APPIMAGE_EXTRACT_AND_RUN=1 ARCH=x86_64 \
    "${ROOT_DIR}/appimagetool-x86_64.AppImage" "${APPDIR}" "${OUTPUT}"
echo "Created ${OUTPUT}"