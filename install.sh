#!/bin/sh
# Install the latest rustradar release binary.
#
#   curl -sSfL https://raw.githubusercontent.com/0xh7ml/rustradar/main/install.sh | sh
#
# Environment:
#   RUSTRADAR_VERSION  release tag to install, e.g. v0.2.0 (default: latest)
#   INSTALL_DIR       install directory (default: $HOME/.local/bin)
set -eu

REPO="0xh7ml/rustradar"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

fail() { echo "error: $*" >&2; exit 1; }

case "$(uname -s)" in
  Linux) os="unknown-linux-musl" ;;
  Darwin) os="apple-darwin" ;;
  *) fail "unsupported OS $(uname -s); on Windows download the .zip from https://github.com/$REPO/releases" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch="x86_64" ;;
  aarch64 | arm64) arch="aarch64" ;;
  *) fail "unsupported CPU $(uname -m)" ;;
esac
target="$arch-$os"

tag="${RUSTRADAR_VERSION:-}"
if [ -z "$tag" ]; then
  tag=$(curl -sSfL "https://api.github.com/repos/$REPO/releases/latest" |
    sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
  [ -n "$tag" ] || fail "could not find the latest release of $REPO"
fi

archive="rustradar-$tag-$target.tar.gz"
base="https://github.com/$REPO/releases/download/$tag"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $archive"
curl -sSfL "$base/$archive" -o "$tmp/$archive" || fail "no release archive at $base/$archive"
curl -sSfL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" || fail "release has no SHA256SUMS"

expected=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$archive" | awk '{ print $1 }')
else
  actual=$(shasum -a 256 "$tmp/$archive" | awk '{ print $1 }')
fi
[ -n "$expected" ] && [ "$expected" = "$actual" ] || fail "checksum mismatch for $archive"

tar -xzf "$tmp/$archive" -C "$tmp" rustradar
mkdir -p "$INSTALL_DIR"
cp "$tmp/rustradar" "$INSTALL_DIR/rustradar.tmp"
chmod 755 "$INSTALL_DIR/rustradar.tmp"
mv "$INSTALL_DIR/rustradar.tmp" "$INSTALL_DIR/rustradar"

echo "Installed rustradar $tag to $INSTALL_DIR/rustradar"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "Add $INSTALL_DIR to your PATH, e.g.: export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac
