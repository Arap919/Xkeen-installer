#!/usr/bin/env bash
set -euo pipefail
version="${1:?Usage: package.sh VERSION}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
stage="build/deb"
mkdir -p "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/share/applications" "$stage/usr/share/icons/hicolor/256x256/apps" release
install -m 755 build/bin/xkeen-installer "$stage/usr/bin/xkeen-installer"
install -m 644 build/appicon.png "$stage/usr/share/icons/hicolor/256x256/apps/xkeen-installer.png"
cat > "$stage/DEBIAN/control" <<EOF
Package: xkeen-installer
Version: $version
Section: net
Priority: optional
Architecture: amd64
Maintainer: Arap919 <42357208+Arap919@users.noreply.github.com>
Depends: libgtk-3-0t64, libwebkit2gtk-4.1-0
Description: Graphical XKeen installer for Keenetic routers
EOF
cat > "$stage/usr/share/applications/xkeen-installer.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=XKeen Installer
Comment=Install XKeen on a Keenetic router
Exec=xkeen-installer
Icon=xkeen-installer
Terminal=false
Categories=Network;Utility;
EOF
chmod 755 "$stage" "$stage/DEBIAN"
dpkg-deb --root-owner-group --build "$stage" "release/xkeen-installer-$version-linux-amd64.deb"
