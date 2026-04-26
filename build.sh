#!/usr/bin/env bash
# build.sh — Build iBoot64Patcher for macOS (arm64 + x86_64 separately) or Linux
# Usage: ./build.sh [--prefix /path/to/install]
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
OPENSSL_VERSION="3.0.15"
OPENSSL_URL="https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"

GIT_DEPENDENCIES="tihmstar/libgeneral,tihmstar/libinsn,tihmstar/libplist,tihmstar/img3tool,tihmstar/img4tool,tihmstar/libpatchfinder"

INSTALL_PREFIX="${1:-$(pwd)/buildroot}"

OS="$(uname -s)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Persistent directories (survive across runs for caching)
BUILD_DIR="${SCRIPT_DIR}/.build-deps"   # source trees live here
CACHE_DIR="${SCRIPT_DIR}/.build-cache"  # stamp files live here

mkdir -p "$BUILD_DIR" "$CACHE_DIR"

log()   { echo "[build.sh] $*"; }
skip()  { echo "[build.sh] SKIP $* (already built)"; }
die()   { echo "[build.sh] ERROR: $*" >&2; exit 1; }

# ── Build-skip helpers ───────────────────────────────────────────────────────
# stamp key is: <dep_name>[_<arch>]   e.g.  "openssl_arm64", "libgeneral_linux"
stamp_file() { echo "${CACHE_DIR}/${1}.done"; }
is_built()   { [[ -f "$(stamp_file "$1")" ]]; }
mark_built() { touch "$(stamp_file "$1")"; }

# ── Platform detection ───────────────────────────────────────────────────────
case "$OS" in
  Linux)  PLATFORM="linux" ;;
  Darwin) PLATFORM="macos" ;;
  *)      die "Unsupported OS: $OS" ;;
esac

# ── CPU count helper ─────────────────────────────────────────────────────────
ncpu() { nproc 2>/dev/null || sysctl -n hw.logicalcpu; }

# ════════════════════════════════════════════════════════════════════════════
# Generic autotools builder (Linux / system-wide install)
# ════════════════════════════════════════════════════════════════════════════
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
  make -j"$(ncpu)"
  sudo make install
  cd "$SCRIPT_DIR"
}

# ════════════════════════════════════════════════════════════════════════════
# Generic autotools builder for a specific arch into a specific prefix (macOS)
# ════════════════════════════════════════════════════════════════════════════
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
  make -j"$(ncpu)"
  make install
  cd "$SCRIPT_DIR"
}

# ════════════════════════════════════════════════════════════════════════════
# OpenSSL 3.0.15 — build from source
# ════════════════════════════════════════════════════════════════════════════

# Linux: build OpenSSL into /usr/local (system-wide, static)
build_openssl_linux() {
  local stamp="openssl_linux"
  if is_built "$stamp"; then skip "openssl ${OPENSSL_VERSION} (linux)"; return; fi

  log "Building OpenSSL ${OPENSSL_VERSION} (Linux)..."
  local src_dir="${BUILD_DIR}/openssl-${OPENSSL_VERSION}"

  if [ ! -d "$src_dir" ]; then
    wget -q "$OPENSSL_URL" -O "${BUILD_DIR}/openssl.tar.gz"
    tar -xzf "${BUILD_DIR}/openssl.tar.gz" -C "$BUILD_DIR"
    rm -f "${BUILD_DIR}/openssl.tar.gz"
  fi

  cd "$src_dir"
  ./Configure \
    linux-$(uname -m) \
    --prefix=/usr/local \
    --openssldir=/usr/local/etc/ssl \
    no-shared \
    no-tests \
    -fPIC
  make -j"$(ncpu)"
  sudo make install_sw   # install_sw skips man pages — faster
  cd "$SCRIPT_DIR"

  mark_built "$stamp"
  log "  OpenSSL ${OPENSSL_VERSION} installed → /usr/local"
}

# macOS: build OpenSSL for a single arch into an arch sysroot
build_openssl_macos_arch() {
  local arch="$1"
  local prefix="$2"   # e.g. $WORK_DIR/sysroot_arm64

  local stamp="openssl_${OPENSSL_VERSION}_${arch}"
  if is_built "$stamp"; then skip "openssl ${OPENSSL_VERSION} ($arch)"; return; fi

  log "Building OpenSSL ${OPENSSL_VERSION} ($arch)..."

  local src_base="${BUILD_DIR}/openssl-${OPENSSL_VERSION}"
  local src_dir="${BUILD_DIR}/openssl-${OPENSSL_VERSION}_${arch}"

  # Download once, copy per arch so parallel builds don't clobber each other
  if [ ! -d "$src_base" ]; then
    curl -fsSL "$OPENSSL_URL" -o "${BUILD_DIR}/openssl.tar.gz"
    tar -xzf "${BUILD_DIR}/openssl.tar.gz" -C "$BUILD_DIR"
    rm -f "${BUILD_DIR}/openssl.tar.gz"
  fi
  [ -d "$src_dir" ] || cp -r "$src_base" "$src_dir"

  local sdk ossl_target
  sdk="$(xcrun --sdk macosx --show-sdk-path)"

  # OpenSSL uses its own target names, not autoconf triples
  case "$arch" in
    arm64)  ossl_target="darwin64-arm64-cc"  ;;
    x86_64) ossl_target="darwin64-x86_64-cc" ;;
    *)      die "Unknown arch for OpenSSL: $arch" ;;
  esac

  cd "$src_dir"
  ./Configure \
    "$ossl_target" \
    --prefix="$prefix" \
    --openssldir="${prefix}/etc/ssl" \
    no-shared \
    no-tests \
    -mmacosx-version-min=10.13 \
    -isysroot "$sdk" \
    "-arch $arch"
  make -j"$(ncpu)"
  make install_sw
  cd "$SCRIPT_DIR"

  # Fix the prefix in the generated .pc files so pkg-config resolves correctly
  if [ -d "${prefix}/lib/pkgconfig" ]; then
    local sed_i
    # BSD sed (macOS) requires an explicit extension argument for -i
    sed_i=(-i '')
    sed "${sed_i[@]}" "s|^prefix=.*|prefix=${prefix}|" \
      "${prefix}/lib/pkgconfig"/openssl.pc \
      "${prefix}/lib/pkgconfig"/libssl.pc \
      "${prefix}/lib/pkgconfig"/libcrypto.pc 2>/dev/null || true
  fi

  mark_built "$stamp"
  log "  OpenSSL ${OPENSSL_VERSION} ($arch) → ${prefix}"
}

# ════════════════════════════════════════════════════════════════════════════
# Linux: install pre-dependencies
# ════════════════════════════════════════════════════════════════════════════
install_predeps_linux() {
  log "Installing system packages..."
  sudo apt-get update -qq
  sudo apt-get install -y \
    build-essential autoconf automake libtool pkg-config \
    libcurl4-openssl-dev libzip-dev wget

  build_openssl_linux

  # libplist (static)
  local stamp="libplist_linux"
  if is_built "$stamp"; then
    skip "libplist (linux)"
  else
    log "Building libplist (static)..."
    local src_dir="${BUILD_DIR}/libplist"
    [ -d "$src_dir" ] || \
      git clone --branch 2.3.0 --depth 1 \
        https://github.com/libimobiledevice/libplist "$src_dir"
    cd "$src_dir"
    ./autogen.sh --without-cython --enable-static --disable-shared \
      CFLAGS="-fPIC" CXXFLAGS="-fPIC"
    make -j"$(ncpu)"
    sudo make install
    cd "$SCRIPT_DIR"
    mark_built "$stamp"
  fi

  # lzfse (static, fPIC)
  local stamp_lzfse="lzfse_linux"
  if is_built "$stamp_lzfse"; then
    skip "lzfse (linux)"
  else
    log "Building lzfse..."
    local lzfse_dir="${BUILD_DIR}/lzfse"
    [ -d "$lzfse_dir" ] || git clone https://github.com/lzfse/lzfse.git "$lzfse_dir"
    make -C "$lzfse_dir" CFLAGS="-fPIC" -j"$(ncpu)"
    sudo make -C "$lzfse_dir" install INSTALL_PREFIX=/usr/local
    mark_built "$stamp_lzfse"
  fi

  # cctools headers (needed for Mach-O types on Linux)
  local stamp_cc="cctools_linux"
  if is_built "$stamp_cc"; then
    skip "cctools headers (linux)"
  else
    log "Installing cctools headers..."
    local cctools_ver="cctools-973.0.1"
    local cctools_dir="${BUILD_DIR}/cctools_src"
    if [ ! -d "$cctools_dir" ]; then
      wget -q "https://github.com/apple-oss-distributions/cctools/archive/refs/tags/${cctools_ver}.tar.gz" \
        -O "${BUILD_DIR}/cctools.tar.gz"
      mkdir -p "$cctools_dir"
      tar -xzf "${BUILD_DIR}/cctools.tar.gz" -C "$cctools_dir" --strip-components=1
      rm -f "${BUILD_DIR}/cctools.tar.gz"
    fi

    # Patch loader.h to compile on Linux
    local loader_h="${cctools_dir}/include/mach-o/loader.h"
    sed -i 's_#include_//_g' "$loader_h"
    sed -i -e 's=<stdint.h>=\n#include <stdint.h>\ntypedef int integer_t;\ntypedef integer_t cpu_type_t;\ntypedef integer_t cpu_subtype_t;\ntypedef integer_t cpu_threadtype_t;\ntypedef int vm_prot_t;=g' \
      "$loader_h"
    sudo cp -r "${cctools_dir}/include/"* /usr/local/include/
    mark_built "$stamp_cc"
  fi
}

# ════════════════════════════════════════════════════════════════════════════
# macOS: install toolchain pre-dependencies (Homebrew tools only — no openssl)
# ════════════════════════════════════════════════════════════════════════════
install_predeps_macos() {
  log "Installing Homebrew toolchain packages..."
  # openssl intentionally omitted — we build it from source per-arch below
  brew install autoconf automake libtool pkg-config libzip
}

# ════════════════════════════════════════════════════════════════════════════
# libplist: build for a single arch into an arch prefix (macOS)
# ════════════════════════════════════════════════════════════════════════════
build_libplist_for_arch() {
  local arch="$1"
  local prefix="$2"

  local stamp="libplist_${arch}"
  if is_built "$stamp"; then skip "libplist ($arch)"; return; fi

  log "Building libplist ($arch)..."

  local sdk plist_src slice_src
  sdk="$(xcrun --sdk macosx --show-sdk-path)"
  plist_src="${BUILD_DIR}/libplist_src"

  # Clone once, copy per arch
  if [ ! -d "$plist_src" ]; then
    git clone --branch 2.3.0 --depth 1 \
      https://github.com/libimobiledevice/libplist "$plist_src"
  fi

  slice_src="${BUILD_DIR}/libplist_src_${arch}"
  [ -d "$slice_src" ] || cp -r "$plist_src" "$slice_src"

  cd "$slice_src"
  ./autogen.sh \
    --without-cython --enable-static --disable-shared \
    --prefix="$prefix" \
    --host="${arch}-apple-darwin" \
    CFLAGS="-arch $arch -isysroot $sdk -mmacosx-version-min=10.13 -fPIC" \
    CXXFLAGS="-arch $arch -isysroot $sdk -mmacosx-version-min=10.13 -fPIC" \
    LDFLAGS="-arch $arch"
  make -j"$(ncpu)"
  make install
  cd "$SCRIPT_DIR"

  # Fix prefix in .pc files
  if [ -d "${prefix}/lib/pkgconfig" ]; then
    sed -i '' "s|^prefix=.*|prefix=${prefix}|" \
      "${prefix}/lib/pkgconfig"/libplist*.pc 2>/dev/null || true
  fi

  mark_built "$stamp"
}

# ════════════════════════════════════════════════════════════════════════════
# Linux: build git dependencies
# ════════════════════════════════════════════════════════════════════════════
build_git_deps_linux() {
  log "Building git dependencies (Linux)..."
  local dep_dir="${BUILD_DIR}/deps_linux"
  mkdir -p "$dep_dir"

  IFS=',' read -r -a deps <<< "$GIT_DEPENDENCIES"
  for d in "${deps[@]}"; do
    local repo stamp
    repo="$(echo "$d" | cut -d'/' -f2)"
    stamp="${repo}_linux"

    if is_built "$stamp"; then
      skip "$repo (linux)"
      continue
    fi

    log "  → $repo"
    local src_dir="${dep_dir}/${repo}"
    [ -d "$src_dir" ] || git clone "https://github.com/$d.git" "$src_dir"
    build_autotools "$src_dir" --enable-static --disable-shared
    mark_built "$stamp"
  done
}

# ════════════════════════════════════════════════════════════════════════════
# macOS: build git dependencies for a single arch
# ════════════════════════════════════════════════════════════════════════════
build_git_deps_macos_arch() {
  local arch="$1"
  local prefix="$2"

  log "Building git dependencies ($arch)..."
  local dep_dir="${BUILD_DIR}/deps_${arch}"
  mkdir -p "$dep_dir"

  IFS=',' read -r -a deps <<< "$GIT_DEPENDENCIES"
  for d in "${deps[@]}"; do
    local repo stamp
    repo="$(echo "$d" | cut -d'/' -f2)"
    stamp="${repo}_${arch}"

    if is_built "$stamp"; then
      skip "$repo ($arch)"
      continue
    fi

    log "  → $repo ($arch)"
    local src_dir="${dep_dir}/${repo}"
    [ -d "$src_dir" ] || git clone "https://github.com/$d.git" "$src_dir"
    build_autotools_for_arch "$arch" "$src_dir" "$prefix"
    mark_built "$stamp"
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
  build_dir="${BUILD_DIR}/build_${arch}"
  mkdir -p "$build_dir"

  cp -r "$SCRIPT_DIR" "$build_dir/src"
  cd "$build_dir/src"
  ./autogen.sh \
    --enable-static --disable-shared \
    --prefix="$sysroot_prefix" \
    --host="${arch}-apple-darwin" \
    CFLAGS="-arch $arch -isysroot $sdk -mmacosx-version-min=10.13 -I${sysroot_prefix}/include" \
    CXXFLAGS="-arch $arch -isysroot $sdk -mmacosx-version-min=10.13 -I${sysroot_prefix}/include" \
    LDFLAGS="-arch $arch -L${sysroot_prefix}/lib" \
    PKG_CONFIG_PATH="${sysroot_prefix}/lib/pkgconfig"
  make -j"$(ncpu)"

  # Install the binary into the arch-specific output directory
  local bin_path bin_name
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
  make -j"$(ncpu)"
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
    sysroot="${BUILD_DIR}/sysroot_${arch}"
    out="$INSTALL_PREFIX/${arch}"
    mkdir -p "$sysroot" "$out"


    # ── pkg-config search paths ──────────────────────────────────────────────────
    export PKG_CONFIG_PATH="$sysroot/lib/pkgconfig:/usr/local/lib/pkgconfig:/usr/lib/pkgconfig"
    export PKG_CONFIG_LIBDIR="$sysroot/lib/pkgconfig:/usr/local/lib/pkgconfig:/usr/lib/pkgconfig"
    export PKG_CONFIG_SYSROOT_DIR="$sysroot"

    export libgeneral_CFLAGS="-I$sysroot/include"
    export libgeneral_LIBS="-L$sysroot/lib"

    build_openssl_macos_arch  "$arch" "$sysroot"
    build_libplist_for_arch   "$arch" "$sysroot"
    build_git_deps_macos_arch "$arch" "$sysroot"
    build_main_macos_arch     "$arch" "$sysroot" "$out"
  done

  log "Done!"
  log "  arm64  → $INSTALL_PREFIX/arm64/bin/"
  log "  x86_64 → $INSTALL_PREFIX/x86_64/bin/"
fi
