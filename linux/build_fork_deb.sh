#!/bin/bash
# Packages the eMudhra fork as proxypin-emudhra.deb so it can coexist with the
# upstream ProxyPin deb: different package name, install dir, .desktop file and
# application id (see linux/CMakeLists.txt).
# Run `flutter build linux --release` first.
set -euo pipefail
cd "$(dirname "$0")/../build/linux/x64/release"

if [ ! -d bundle ]; then
  echo "error: build/linux/x64/release/bundle not found; run 'flutter build linux --release' first" >&2
  exit 1
fi

VERSION=1.3.3-1
DEB=proxypin-emudhra_${VERSION}_amd64.deb
rm -f "${DEB}"

rm -rf package-fork
mkdir -p package-fork/opt package-fork/usr/share/applications
cp -r bundle package-fork/opt/proxypin-emudhra
cp ../../../../linux/proxypin-emudhra.desktop package-fork/usr/share/applications/

# du before DEBIAN exists so Installed-Size reflects payload only
INSTALLED_SIZE=$(du -sk package-fork | awk '{print $1}')

mkdir -p package-fork/DEBIAN
cat > package-fork/DEBIAN/control <<EOF
Package: proxypin-emudhra
Version: ${VERSION}
Installed-Size: ${INSTALLED_SIZE}
Priority: optional
Architecture: amd64
Depends: ca-certificates, libc6, libgcc-s1, libgtk-3-0, libayatana-appindicator3-1
Section: utils
Maintainer: wanghongenpin@gmail.com
Homepage: https://github.com/wanghongenpin/proxypin
Description: http/https Capture packets (eMudhra CA fork)
 Fork of ProxyPin that signs forged certificates with the compromised
 eMudhra intermediate CAs, enabling MITM without installing a CA on
 unpatched client devices.
EOF

# dpkg-deb also generates these when missing; do it here for the fallback path
( cd package-fork && find opt usr -type f -exec md5sum {} + > DEBIAN/md5sums )

# Prefer dpkg tooling when present (Debian-family); otherwise assemble the
# .deb with ar/tar (a v2.0 deb is just debian-binary + control.tar + data.tar),
# so packaging also works on Arch without installing dpkg.
if command -v dpkg-deb >/dev/null 2>&1; then
  dpkg-deb -b package-fork "${DEB}"
elif command -v dpkg >/dev/null 2>&1; then
  dpkg -b package-fork "${DEB}"
else
  (
    cd package-fork
    tar --owner=0 --group=0 --numeric-owner -czf ../control.tar.gz -C DEBIAN .
    tar --owner=0 --group=0 --numeric-owner -czf ../data.tar.gz opt usr
    printf '2.0\n' > ../debian-binary
    cd ..
    ar r "${DEB}" debian-binary control.tar.gz data.tar.gz > /dev/null
    rm -f debian-binary control.tar.gz data.tar.gz
  )
  echo "${DEB}"
fi
