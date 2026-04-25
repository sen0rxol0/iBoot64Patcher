#!/usr/bin/env bash
# build.sh — Build iBoot64Patcher for macOS (arm64 + x86_64 separately) or Linux
# Usage: ./build.sh [--prefix /path/to/install]
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
GIT_DEPENDENCIES="tihmstar/libgeneral,tihmstar/libinsn,tihmstar/libplist,tihmstar/img3tool,tihmstar/img4tool,tihmstar/libpatchfinder"
MAC_DYNAMIC_LIBS="openssl"
INSTALL_PREFIX="${1:-$(pwd)/buildroot}"

OS="$(uname -s)"
ARCH="$(uname -m)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

log()  { echo "[build.sh] $*"; }
die()  { echo "[build.sh] ERROR: $*" >&2; exit 1; }

# ── Platform detection ───────────────────────────────────────────────────────
case "$OS" in
  Linux)  PLATFORM="linux" ;;
  Darwin) PLATFORM="macos" ;;
  *)      die "Unsupported OS: $OS" ;;
esac

# ── pkg-config search paths ──────────────────────────────────────────────────
export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:/usr/lib/pkgconfig"
export PKG_CONFIG_LIBDIR="/usr/local/lib/pkgconfig:/usr/lib/pkgconfig"
export PKG_CONFIG_SYSROOT_DIR="/"

export libgeneral_CFLAGS="-I/usr/local/include"
export libgeneral_LIBS="-L/usr/local/lib/libgeneral.a"

# ── Helper: build a single autotools project ─────────────────────────────────
build_autotools() {
  local src_dir="$1"
  shift
  local extra_args=("$@")

  cd "$src_dir"
  if [ -f autogen.sh ]; then
    ./autogen.sh "${extra_args[@]}"
  elif [ -f configure ]; then
    ./configure "${extra_args[@]}"
  else
    die "No autogen.sh or configure found in $src_dir"
  fi
  make -j"$(nproc 2>/dev/null || sysctl -n hw.logicalcpu)"
  sudo make install
  cd "$SCRIPT_DIR"
}

# ── Helper: build a project for a specific arch into a specific prefix ────────
build_autotools_for_arch() {
  local arch="$1"
  local src_dir="$2"
  local prefix="$3"

  local sdk
  sdk="$(xcrun --sdk macosx --show-sdk-path)"

  cd "$src_dir"
  if [ -f autogen.sh ]; then
    ./autogen.sh \
      --enable-static --disable-shared \
      --prefix="$prefix" \
      --host="${arch}-apple-darwin" \
      CFLAGS="-arch $arch -isysroot $sdk -mmacosx-version-min=10.13" \
      CXXFLAGS="-stdlib=libc++ -arch $arch -isysroot $sdk -mmacosx-version-min=10.13" \
      LDFLAGS="-arch $arch"
  else
    die "No autogen.sh found in $src_dir"
  fi
  make -j"$(sysctl -n hw.logicalcpu)"
  make install
  cd "$SCRIPT_DIR"
}

# ════════════════════════════════════════════════════════════════════════════
# Linux: install pre-dependencies
# ════════════════════════════════════════════════════════════════════════════
install_predeps_linux() {
  log "Installing system packages..."
  sudo apt-get update -qq
  sudo apt-get install -y \
    build-essential autoconf automake libtool pkg-config \
    libssl-dev libcurl4-openssl-dev libzip-dev

  # libplist (static)
  log "Building libplist (static)..."
  git clone --branch 2.3.0 --depth 1 https://github.com/libimobiledevice/libplist "$WORK_DIR/libplist"
  cd "$WORK_DIR/libplist"
  ./autogen.sh --without-cython --enable-static --disable-shared \
    CFLAGS="-fPIC" CXXFLAGS="-fPIC"
  make -j"$(nproc)"
  sudo make install
  cd "$SCRIPT_DIR"

  # lzfse (static, fPIC)
  log "Building lzfse..."
  git clone https://github.com/lzfse/lzfse.git "$WORK_DIR/lzfse"
  make -C "$WORK_DIR/lzfse" CFLAGS="-fPIC" -j"$(nproc)"
  sudo make -C "$WORK_DIR/lzfse" install INSTALL_PREFIX=/usr/local

  # cctools headers (needed for Mach-O types on Linux)
  log "Installing cctools headers..."
  local cctools_ver="cctools-973.0.1"
  wget -q "https://github.com/apple-oss-distributions/cctools/archive/refs/tags/${cctools_ver}.tar.gz" \
    -O "$WORK_DIR/cctools.tar.gz"
  mkdir -p "$WORK_DIR/cctools_src"
  tar -xzf "$WORK_DIR/cctools.tar.gz" -C "$WORK_DIR/cctools_src" --strip-components=1

  # Patch loader.h to compile on Linux
  local loader_h="$WORK_DIR/cctools_src/include/mach-o/loader.h"
  sed -i 's_#include_//_g' "$loader_h"
  sed -i -e 's=<stdint.h>=\n#include <stdint.h>\ntypedef int integer_t;\ntypedef integer_t cpu_type_t;\ntypedef integer_t cpu_subtype_t;\ntypedef integer_t cpu_threadtype_t;\ntypedef int vm_prot_t;=g' \
    "$loader_h"
  sudo cp -r "$WORK_DIR/cctools_src/include/"* /usr/local/include/
}

# ════════════════════════════════════════════════════════════════════════════
# macOS: install pre-dependencies (shared; libplist built per-arch separately)
# ════════════════════════════════════════════════════════════════════════════
install_predeps_macos() {
  log "Installing Homebrew packages..."
  brew install autoconf automake libtool pkg-config libzip
  brew reinstall openssl

  # Ensure openssl pkg-config is visible system-wide
  if [ ! -e /usr/local/lib/pkgconfig/openssl.pc ]; then
    local ossl_prefix
    ossl_prefix="$(brew --prefix openssl)"
    sudo mkdir -p /usr/local/lib/pkgconfig/
    sudo cp -r "$ossl_prefix/lib/pkgconfig/"* /usr/local/lib/pkgconfig/
  fi
}

# ── Helper: build libplist for a single arch and install into an arch prefix ──
build_libplist_for_arch() {
  local arch="$1"
  local prefix="$2"

  local sdk plist_src slice_src
  sdk="$(xcrun --sdk macosx --show-sdk-path)"
  plist_src="$WORK_DIR/libplist_src"

  # Clone once, reuse for each arch
  if [ ! -d "$plist_src" ]; then
    git clone --branch 2.3.0 --depth 1 https://github.com/libimobiledevice/libplist "$plist_src"
  fi

  slice_src="$WORK_DIR/libplist_src_${arch}"
  cp -r "$plist_src" "$slice_src"

  cd "$slice_src"
  ./autogen.sh \
    --without-cython --enable-static --disable-shared \
    --prefix="$prefix" \
    --host="${arch}-apple-darwin" \
    CFLAGS="-arch $arch -isysroot $sdk -mmacosx-version-min=10.13 -fPIC" \
    CXXFLAGS="-arch $arch -isysroot $sdk -mmacosx-version-min=10.13 -fPIC" \
    LDFLAGS="-arch $arch"
  make -j"$(sysctl -n hw.logicalcpu)"
  make install
  cd "$SCRIPT_DIR"

  # Register pkg-config .pc files under the arch prefix
  if [ -d "$prefix/lib/pkgconfig" ]; then
    sed -i '' "s|^prefix=.*|prefix=$prefix|" "$prefix/lib/pkgconfig"/libplist*.pc 2>/dev/null || true
  fi
}

# ════════════════════════════════════════════════════════════════════════════
# Linux: build git dependencies
# ════════════════════════════════════════════════════════════════════════════
build_git_deps_linux() {
  log "Building git dependencies (Linux)..."
  local dep_dir="$WORK_DIR/deps"
  mkdir -p "$dep_dir"

  IFS=',' read -r -a deps <<< "$GIT_DEPENDENCIES"
  for d in "${deps[@]}"; do
    local repo
    repo="$(echo "$d" | cut -d'/' -f2)"
    log "  → $repo"
    git clone "https://github.com/$d.git" "$dep_dir/$repo"
    build_autotools "$dep_dir/$repo" --enable-static --disable-shared
  done
}

# ════════════════════════════════════════════════════════════════════════════
# macOS: build git dependencies for a single arch
# ════════════════════════════════════════════════════════════════════════════
build_git_deps_macos_arch() {
  local arch="$1"
  local prefix="$2"

  log "Building git dependencies for $arch..."
  local dep_dir="$WORK_DIR/deps_${arch}"
  mkdir -p "$dep_dir"

  IFS=',' read -r -a deps <<< "$GIT_DEPENDENCIES"
  for d in "${deps[@]}"; do
    local repo src_dir
    repo="$(echo "$d" | cut -d'/' -f2)"
    log "  → $repo ($arch)"
    src_dir="$dep_dir/$repo"
    git clone "https://github.com/$d.git" "$src_dir"
    build_autotools_for_arch "$arch" "$src_dir" "$prefix"
  done
}

# ════════════════════════════════════════════════════════════════════════════
# macOS: hide/restore dynamic libs to force static linking
# ════════════════════════════════════════════════════════════════════════════
hide_dylibs() {
  log "Hiding dynamic libs to force static linking: $MAC_DYNAMIC_LIBS"
  IFS=',' read -r -a libs <<< "$MAC_DYNAMIC_LIBS"
  for lib in "${libs[@]}"; do
    local prefix
    prefix="$(brew --prefix "$lib")"
    find "$prefix" -name "*.dylib" -exec mv {} {}.bak \;
  done
}

restore_dylibs() {
  log "Restoring dynamic libs..."
  IFS=',' read -r -a libs <<< "$MAC_DYNAMIC_LIBS"
  for lib in "${libs[@]}"; do
    local prefix
    prefix="$(brew --prefix "$lib")"
    find "$prefix" -name "*.dylib.bak" | while read -r f; do
      mv "$f" "${f%.bak}"
    done
  done
}

# ════════════════════════════════════════════════════════════════════════════
# macOS: build the main project for a single arch
# ════════════════════════════════════════════════════════════════════════════
build_main_macos_arch() {
  local arch="$1"
  local sysroot_prefix="$2"   # where deps were installed for this arch
  local out_prefix="$3"       # where to install the final binary

  log "Building iBoot64Patcher ($arch)..."

  local sdk build_dir
  sdk="$(xcrun --sdk macosx --show-sdk-path)"
  build_dir="$WORK_DIR/build_${arch}"
  mkdir -p "$build_dir"

  hide_dylibs

  cp -r "$SCRIPT_DIR" "$build_dir/src"
  cd "$build_dir/src"
  ./autogen.sh \
    --enable-static --disable-shared \
    --prefix="$sysroot_prefix" \
    --host="${arch}-apple-darwin" \
    CFLAGS="-arch $arch -isysroot $sdk -mmacosx-version-min=10.13 -I${sysroot_prefix}/include" \
    CXXFLAGS="-arch $arch -isysroot $sdk -mmacosx-version-min=10.13 -I${sysroot_prefix}/include" \
    LDFLAGS="-arch $arch -L${sysroot_prefix}/lib" \
    PKG_CONFIG_PATH="${sysroot_prefix}/lib/pkgconfig:/usr/local/lib/pkgconfig"
  make -j"$(sysctl -n hw.logicalcpu)"

  restore_dylibs

  # Install the binary into the arch-specific output directory
  local bin_name bin_path
  bin_path="$(find "$build_dir/src" -maxdepth 3 -type f -perm +111 ! -name "*.sh" ! -name "*.py" | head -1)"
  bin_name="$(basename "$bin_path")"

  mkdir -p "$out_prefix/bin"
  cp "$bin_path" "$out_prefix/bin/$bin_name"
  log "  → $out_prefix/bin/$bin_name"

  cd "$SCRIPT_DIR"
}

# ════════════════════════════════════════════════════════════════════════════
# Linux: build and install the main project
# ════════════════════════════════════════════════════════════════════════════
build_main_linux() {
  log "Building iBoot64Patcher (Linux)..."
  cd "$SCRIPT_DIR"
  ./autogen.sh --enable-static --disable-shared
  make -j"$(nproc)"
  make DESTDIR="$INSTALL_PREFIX" install
}

# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════
mkdir -p "$INSTALL_PREFIX"

if [ "$PLATFORM" = "linux" ]; then
  install_predeps_linux
  build_git_deps_linux
  build_main_linux
  log "Done! Output in: $INSTALL_PREFIX"

elif [ "$PLATFORM" = "macos" ]; then
  install_predeps_macos

  for arch in arm64 x86_64; do
    log "═══ Building $arch ═══"
    sysroot="$WORK_DIR/sysroot_${arch}"
    out="$INSTALL_PREFIX/${arch}"
    mkdir -p "$sysroot" "$out"

    build_libplist_for_arch "$arch" "$sysroot"
    build_git_deps_macos_arch "$arch" "$sysroot"
    build_main_macos_arch "$arch" "$sysroot" "$out"
  done

  log "Done!"
  log "  arm64  → $INSTALL_PREFIX/arm64/bin/"
  log "  x86_64 → $INSTALL_PREFIX/x86_64/bin/"
fi
