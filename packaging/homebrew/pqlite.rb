# PQLite Homebrew Formula
# Copyright (c) 2025-2026 Dyber, Inc.
#
# Install: brew install dyber-pqc/tap/pqlite
# Or:      brew tap dyber-pqc/tap && brew install pqlite

class Pqlite < Formula
  desc "Post-Quantum SQLite - Quantum-resistant database encryption"
  homepage "https://github.com/dyber-pqc/PQLite"
  url "https://github.com/dyber-pqc/PQLite/archive/refs/tags/v1.0.0.tar.gz"
  # sha256 "UPDATE_WITH_ACTUAL_SHA256"
  license "MIT"

  depends_on "cmake" => :build
  depends_on "ninja" => :build
  depends_on "pkg-config" => :build
  depends_on "tcl-tk" => :build
  depends_on "liboqs"
  depends_on "openssl@3"

  def install
    # Generate SQLite amalgamation
    system "chmod", "+x", "configure",
           "autosetup/autosetup-find-tclsh",
           "autosetup/autosetup",
           "autosetup/autosetup-test-tclsh",
           "autosetup/autosetup-config.guess",
           "autosetup/autosetup-config.sub"
    system "./configure"
    system "make", "sqlite3.c"
    system "make", "shell.c"

    # Build with CMake
    args = %W[
      -DPQLITE_PQC=ON
      -DCMAKE_BUILD_TYPE=Release
      -DCMAKE_INSTALL_RPATH=#{lib}
    ]

    system "cmake", "-S", ".", "-B", "build", "-GNinja", *args, *std_cmake_args
    system "cmake", "--build", "build"
    system "cmake", "--install", "build"

    # Install pkg-config file
    (lib/"pkgconfig/pqlite3.pc").write <<~EOS
      prefix=#{prefix}
      exec_prefix=${prefix}
      libdir=#{lib}
      includedir=#{include}

      Name: PQLite
      Description: Post-Quantum SQLite - Quantum-resistant database encryption
      Version: #{version}
      Libs: -L${libdir} -lpqlite3
      Cflags: -I${includedir}
    EOS
  end

  test do
    system "#{bin}/pqlite3", ":memory:", "SELECT pqc_version();"
    system "#{bin}/pqlite3", ":memory:", "SELECT 'PQLite works!';"
  end
end
