#!/bin/sh
# Builds dist/ADSearchTools.app (universal arm64 + x86_64, macOS 13+, ad-hoc signed) and dist/ADSearchTools.dmg.
# Needs only Command Line Tools: xcode-select --install
set -eu
cd "$(dirname "$0")/.."
APP=ADSearchTools
VERSION=${VERSION:-1.0}
BUILD=$(git rev-list --count HEAD 2>/dev/null || echo 1)
DIST=dist
rm -rf "$DIST" && mkdir -p "$DIST"

for arch in arm64 x86_64; do
  swift build -c release --arch "$arch" --product "$APP" 2>&1 | grep -E "error|Compiling|Build" | grep -v warning || true
done
BIN_ARM=.build/arm64-apple-macosx/release/$APP
BIN_X86=.build/x86_64-apple-macosx/release/$APP
test -x "$BIN_ARM" && test -x "$BIN_X86"

C="$DIST/$APP.app/Contents"
mkdir -p "$C/MacOS" "$C/Resources/ru.lproj"
lipo -create -output "$C/MacOS/$APP" "$BIN_ARM" "$BIN_X86"
swift scripts/make-icon.swift "$DIST/AppIcon.iconset"
iconutil -c icns -o "$C/Resources/AppIcon.icns" "$DIST/AppIcon.iconset"
rm -rf "$DIST/AppIcon.iconset"
# The ru.lproj marker makes AppKit's own menu items (Hide, Quit, Window…) come up in Russian.
printf '"CFBundleName" = "ADSearchTools";\n' > "$C/Resources/ru.lproj/InfoPlist.strings"

cat > "$C/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>$APP</string>
  <key>CFBundleIdentifier</key><string>local.adsearchtools.app</string>
  <key>CFBundleName</key><string>$APP</string>
  <key>CFBundleDisplayName</key><string>ADSearchTools</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$BUILD</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundleDevelopmentRegion</key><string>ru</string>
  <key>CFBundleLocalizations</key><array><string>ru</string></array>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSHumanReadableCopyright</key><string>Внутренний инструмент администрирования Active Directory</string>
</dict></plist>
PLIST

codesign --force --sign - --timestamp=none "$DIST/$APP.app"
codesign --verify --strict "$DIST/$APP.app"

STAGE="$DIST/dmg"
mkdir -p "$STAGE"
cp -R "$DIST/$APP.app" "$STAGE/"
ln -s /Applications "$STAGE/Программы"
cp scripts/INSTALL.txt "$STAGE/Как установить.txt"
hdiutil create -quiet -volname "$APP" -srcfolder "$STAGE" -ov -format UDZO "$DIST/$APP.dmg"
rm -rf "$STAGE"
echo "$DIST/$APP.app"
echo "$DIST/$APP.dmg ($(du -h "$DIST/$APP.dmg" | cut -f1))"
