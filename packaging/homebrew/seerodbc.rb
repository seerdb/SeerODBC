# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
#
# SPDX-License-Identifier: CC0-1.0

# Homebrew formula for SeerODBC, building from a release tag's source tarball.
# Install it from a tap that carries this file, e.g.:
#   brew tap-new --no-git <you>/seerodbc
#   cp packaging/homebrew/seerodbc.rb \
#      "$(brew --repository)/Library/Taps/<you>/homebrew-seerodbc/Formula/"
#   brew install <you>/seerodbc/seerodbc
# On each release bump `url` to the new tag and `sha256` to its tarball's hash.
class Seerodbc < Formula
  desc "Clean-room thin ODBC driver for Oracle Database (no Oracle client needed)"
  homepage "https://github.com/seerdb/SeerODBC"
  url "https://github.com/seerdb/SeerODBC/archive/refs/tags/0.2.0.tar.gz"
  sha256 "295faf23cbfb0ff3cbd4d1ea50efa417b5b78474ce6b98a9565f5bdab3e52da1"
  license "Apache-2.0"
  head "https://github.com/seerdb/SeerODBC.git", branch: "master"

  depends_on "meson" => :build
  depends_on "ninja" => :build
  depends_on "pkgconf" => :build
  depends_on "openssl@3"
  depends_on "unixodbc"

  def install
    system "meson", "setup", "build", *std_meson_args
    system "meson", "compile", "-C", "build", "--verbose"
    system "meson", "install", "-C", "build"
    (pkgshare/"odbcinst.ini.sample").write <<~EOS
      [SeerODBC]
      Description = Clean-room ODBC driver for Oracle Database
      Driver      = #{opt_lib}/odbc/libseerodbc.dylib
    EOS
  end

  def caveats
    <<~EOS
      Register the driver with unixODBC:
        odbcinst -i -d -f #{opt_pkgshare}/odbcinst.ini.sample
    EOS
  end

  test do
    driver = lib/"odbc/libseerodbc.dylib"
    assert_path_exists driver
    # The ODBC entry points the Driver Manager resolves are exported.
    exports = shell_output("nm -gU #{driver}")
    %w[_SQLDriverConnect _SQLExecDirect _SQLFetch _SQLGetInfo].each do |sym|
      assert_match sym, exports
    end
  end
end
