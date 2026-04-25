#!/usr/bin/env bash
# build.sh — Build iBoot64Patcher for macOS (universal) or Linux
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

# ── macOS: determine target architectures ────────────────────────────────────
if [ "$PLATFORM" = "macos" ]; then
  MACOS_ARCHES=("arm64" "x86_64")
  log "macOS detected — will build universal binary (arm64 + x86_64)"
fi

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

# ── Helper: build a project for a specific arch (macOS only) ─────────────────
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
      CFLAGS="-arch $arch -isysroot $sdk -mmacosx-version-min=10.15" \
      CXXFLAGS="-stdlib=libc++ -arch $arch -isysroot $sdk -mmacosx-version-min=10.15" \
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
  git clone https://github.com/libimobiledevice/libplist "$WORK_DIR/libplist"
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
# macOS: install pre-dependencies
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
# macOS: build git dependencies as universal libs
# ════════════════════════════════════════════════════════════════════════════
build_git_deps_macos() {
  log "Building git dependencies as universal binaries (macOS)..."
  local dep_dir="$WORK_DIR/deps"
  mkdir -p "$dep_dir"

  IFS=',' read -r -a deps <<< "$GIT_DEPENDENCIES"
  for d in "${deps[@]}"; do
    local repo
    repo="$(echo "$d" | cut -d'/' -f2)"
    log "  → $repo (universal)"
    git clone "https://github.com/$d.git" "$dep_dir/$repo"

    local arm_prefix="$WORK_DIR/sysroot_arm64/usr/local"
    local x86_prefix="$WORK_DIR/sysroot_x86_64/usr/local"
    local fat_prefix="/usr/local"

    mkdir -p "$arm_prefix" "$x86_prefix"

    # Build arm64 slice
    local src_arm="$dep_dir/${repo}_arm64"
    cp -r "$dep_dir/$repo" "$src_arm"
    build_autotools_for_arch arm64 "$src_arm" "$arm_prefix"

    # Build x86_64 slice
    local src_x86="$dep_dir/${repo}_x86_64"
    cp -r "$dep_dir/$repo" "$src_x86"
    build_autotools_for_arch x86_64 "$src_x86" "$x86_prefix"

    # Lipo static libs into fat universals and install
    log "    lipo-ing $repo into universal..."
    find "$arm_prefix/lib" -name "*.a" | while read -r arm_lib; do
      local libname
      libname="$(basename "$arm_lib")"
      local x86_lib="$x86_prefix/lib/$libname"
      local fat_lib="$fat_prefix/lib/$libname"
      if [ -f "$x86_lib" ]; then
        sudo mkdir -p "$(dirname "$fat_lib")"
        sudo lipo -create "$arm_lib" "$x86_lib" -output "$fat_lib"
      fi
    done

    # Install headers from arm64 build (arch-independent)
    if [ -d "$arm_prefix/include" ]; then
      sudo cp -r "$arm_prefix/include/"* "$fat_prefix/include/"
    fi
  done
}

# ════════════════════════════════════════════════════════════════════════════
# macOS: hide dynamic libs so linker is forced to use static ones
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
# macOS: build the main project as a universal binary
# ════════════════════════════════════════════════════════════════════════════
build_main_macos_universal() {
  log "Building iBoot64Patcher as universal binary..."

  local sdk
  sdk="$(xcrun --sdk macosx --show-sdk-path)"
  local arm_dir="$WORK_DIR/build_arm64"
  local x86_dir="$WORK_DIR/build_x86_64"

  mkdir -p "$arm_dir" "$x86_dir"

  hide_dylibs

  # arm64
  log "  Compiling arm64 slice..."
  cp -r "$SCRIPT_DIR" "$arm_dir/src"
  cd "$arm_dir/src"
  ./autogen.sh --enable-static --disable-shared \
    CFLAGS="-arch arm64 -isysroot $sdk -mmacosx-version-min=11.0" \
    CXXFLAGS="-arch arm64 -isysroot $sdk -mmacosx-version-min=11.0" \
    LDFLAGS="-arch arm64"
  make -j"$(sysctl -n hw.logicalcpu)"

  # x86_64
  log "  Compiling x86_64 slice..."
  cp -r "$SCRIPT_DIR" "$x86_dir/src"
  cd "$x86_dir/src"
  ./autogen.sh --enable-static --disable-shared \
    CFLAGS="-arch x86_64 -isysroot $sdk -mmacosx-version-min=11.0" \
    CXXFLAGS="-arch x86_64 -isysroot $sdk -mmacosx-version-min=11.0" \
    LDFLAGS="-arch x86_64"
  make -j"$(sysctl -n hw.logicalcpu)"

  restore_dylibs

  # lipo final binary
  log "  Creating universal binary with lipo..."
  local bin_name
  # Find the built executable (usually in src/ or bin/)
  local arm_bin x86_bin
  arm_bin="$(find "$arm_dir/src" -maxdepth 3 -type f -perm +111 ! -name "*.sh" ! -name "*.py" | head -1)"
  x86_bin="$(find "$x86_dir/src" -maxdepth 3 -type f -perm +111 ! -name "*.sh" ! -name "*.py" | head -1)"
  bin_name="$(basename "$arm_bin")"

  sudo mkdir -p "$INSTALL_PREFIX/usr/local/bin"
  sudo lipo -create "$arm_bin" "$x86_bin" -output "$INSTALL_PREFIX/usr/local/bin/$bin_name"

  log "  Universal binary: $INSTALL_PREFIX/usr/local/bin/$bin_name"
  lipo -info "$INSTALL_PREFIX/usr/local/bin/$bin_name"
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
  build_git_deps_macos
  build_main_macos_universal
  log "Done! Universal binary in: $INSTALL_PREFIX/usr/local/bin/"
fi
