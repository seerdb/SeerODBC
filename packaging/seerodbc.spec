# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
#
# SPDX-License-Identifier: CC0-1.0

# RPM spec stub for Fedora. Fill in once there is a tagged release tarball.
Name:           seerodbc
Version:        0.0.0
Release:        %autorelease
Summary:        Clean-room ODBC driver for Oracle Database
License:        Apache-2.0
URL:            https://github.com/lemenkov/seerodbc
VCS:            git:%{url}.git
Source:         %{url}/archive/%{version}/%{name}-%{version}.tar.gz
BuildRequires:  gcc
BuildRequires:  meson
BuildRequires:  ninja-build
BuildRequires:  pkgconfig(openssl)
BuildRequires:  unixODBC-devel
Requires:       odbcinst-generate

%description
SeerODBC lets ODBC consumers talk to an Oracle database by speaking the
Oracle TNS/TTC wire protocol directly, with no Oracle Instant Client.
It is a clean-room implementation (see CONTRIBUTING.md).

%prep
%autosetup -p1 -n %{name}-%{version}

%build
%meson
%meson_build

%install
%meson_install

%files
%license LICENSE
%doc README.md NOTICE packaging/odbcinst.ini.sample docs/*.md
%{_libdir}/odbc/libseerodbc.so
%{_bindir}/freeoracle

%changelog
%autochangelog
