#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Read version from app.py (single source of truth)
VERSION=$(sed -n 's/.*setApplicationVersion("\([^"]*\)").*/\1/p' app.py)
[ -n "$VERSION" ] || { echo "ERROR: Could not extract version from app.py"; exit 1; }
echo "Building SecureOps v${VERSION}..."

# Load pinned tool versions
source packaging/tool_versions.sh

mkdir -p dist/tools

# ─── Stage 1: Fetch Go tools ─────────────────────────────────────────────────
echo ""
echo "=== Stage 1: Fetching Go tools ==="

for ENTRY in \
    "subfinder:$SUBFINDER_VERSION" \
    "dnsx:$DNSX_VERSION" \
    "naabu:$NAABU_VERSION" \
    "httpx:$HTTPX_VERSION" \
    "katana:$KATANA_VERSION" \
    "nuclei:$NUCLEI_VERSION"; do

    TOOL="${ENTRY%%:*}"
    VER="${ENTRY##*:}"
    DEST="dist/tools/${TOOL}"

    if [ -f "$DEST" ]; then
        echo "  (cached) $TOOL"
        continue
    fi

    URL="https://github.com/projectdiscovery/${TOOL}/releases/download/v${VER}/${TOOL}_${VER}_linux_amd64.zip"
    echo "  Downloading $TOOL v${VER}..."
    curl -fsSL "$URL" -o "dist/${TOOL}.zip"
    unzip -j -o "dist/${TOOL}.zip" "${TOOL}" -d dist/tools/
    chmod +x "$DEST"
    rm -f "dist/${TOOL}.zip"
    echo "  Done: $TOOL"
done

# ─── Stage 2: PyInstaller ────────────────────────────────────────────────────
echo ""
echo "=== Stage 2: Building Python bundle ==="

[ -d venv ] || { echo "ERROR: venv/ not found. Run: python3 -m venv venv && pip install -r requirements.txt"; exit 1; }
source venv/bin/activate
pip install -q -r requirements.txt
pip install -q "pyinstaller>=6.0"

pyinstaller secureops.spec --noconfirm

# Copy bundled Go tools into the PyInstaller output directory
cp -r dist/tools dist/secureops/tools
echo "  PyInstaller bundle ready at dist/secureops/"

# ─── Stage 3: Build .deb ─────────────────────────────────────────────────────
echo ""
echo "=== Stage 3: Building .deb ==="

rm -rf dist/deb-staging
mkdir -p dist/deb-staging/DEBIAN
mkdir -p dist/deb-staging/opt/secureops
mkdir -p dist/deb-staging/usr/local/bin
mkdir -p dist/deb-staging/usr/share/applications
mkdir -p dist/deb-staging/usr/share/pixmaps

# App files
cp -r dist/secureops/. dist/deb-staging/opt/secureops/

# Control files (substitute {VERSION} placeholder)
sed "s/{VERSION}/${VERSION}/" packaging/deb/DEBIAN/control \
    > dist/deb-staging/DEBIAN/control
cp packaging/deb/DEBIAN/postinst dist/deb-staging/DEBIAN/postinst
cp packaging/deb/DEBIAN/copyright dist/deb-staging/DEBIAN/copyright
chmod 0755 dist/deb-staging/DEBIAN/postinst

# Thin shell launcher at /usr/local/bin/secureops
cat > dist/deb-staging/usr/local/bin/secureops << 'LAUNCHER'
#!/bin/sh
exec /opt/secureops/secureops "$@"
LAUNCHER
chmod 0755 dist/deb-staging/usr/local/bin/secureops

# Desktop integration
cp packaging/appimage/secureops.desktop \
    dist/deb-staging/usr/share/applications/secureops.desktop
cp packaging/appimage/secureops.svg \
    dist/deb-staging/usr/share/pixmaps/secureops.svg

# Executable permissions on binaries
chmod 0755 dist/deb-staging/opt/secureops/secureops
find dist/deb-staging/opt/secureops/tools -type f -exec chmod 0755 {} \;

DEB_PATH="dist/secureops_${VERSION}_amd64.deb"
dpkg-deb --build --root-owner-group dist/deb-staging "$DEB_PATH"
echo "  Built: $DEB_PATH"

# ─── Stage 4: Build .AppImage ────────────────────────────────────────────────
echo ""
echo "=== Stage 4: Building AppImage ==="

if [ ! -f dist/appimagetool ]; then
    echo "  Downloading appimagetool..."
    curl -fsSL \
        "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage" \
        -o dist/appimagetool
    chmod +x dist/appimagetool
fi

rm -rf dist/AppDir
mkdir -p dist/AppDir/usr/lib/secureops
mkdir -p dist/AppDir/usr/bin

# App files (same PyInstaller output)
cp -r dist/secureops/. dist/AppDir/usr/lib/secureops/
ln -s ../lib/secureops/secureops dist/AppDir/usr/bin/secureops

# AppImage structure
cp packaging/appimage/AppRun dist/AppDir/AppRun
chmod +x dist/AppDir/AppRun
cp packaging/appimage/secureops.desktop dist/AppDir/secureops.desktop
cp packaging/appimage/secureops.svg dist/AppDir/secureops.svg

APPIMAGE_PATH="dist/SecureOps-${VERSION}-x86_64.AppImage"
ARCH=x86_64 dist/appimagetool dist/AppDir "$APPIMAGE_PATH"
echo "  Built: $APPIMAGE_PATH"

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "=== Build complete ==="
echo "  $DEB_PATH"
echo "  $APPIMAGE_PATH"
