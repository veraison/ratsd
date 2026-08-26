# Copyright 2026 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

%{!?version:%global version 0.0.0}
%{!?release:%global release 1}
%global debug_package %{nil}

Name:           veraison-ratsd
Version:        %{version}
Release:        %{release}%{?dist}
Summary:        Veraison RATS conceptual message collection daemon
License:        Apache-2.0
URL:            https://github.com/veraison/ratsd
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  golang >= 1.25
BuildRequires:  make

%description
RATSd is a conceptual message collection daemon for the Veraison project.

%prep
%autosetup

%build
GOFLAGS="-buildvcs=false" %make_build build

%install
install -Dpm 0755 ratsd %{buildroot}%{_bindir}/ratsd
install -Dpm 0755 attesters/bin/tsm.plugin \
  %{buildroot}%{_libexecdir}/veraison-ratsd/plugins/tsm.plugin
install -Dpm 0755 attesters/bin/mocktsm.plugin \
  %{buildroot}%{_libexecdir}/veraison-ratsd/plugins/mocktsm.plugin
install -Dpm 0755 attesters/bin/nvgpu.plugin \
  %{buildroot}%{_libexecdir}/veraison-ratsd/plugins/nvgpu.plugin
install -Dpm 0644 config.yaml %{buildroot}%{_sysconfdir}/veraison-ratsd/config.yaml
sed -i 's|plugin-dir: attesters/bin|plugin-dir: %{_libexecdir}/veraison-ratsd/plugins|' \
  %{buildroot}%{_sysconfdir}/veraison-ratsd/config.yaml

%files
%license LICENSE
%doc README.md
%{_bindir}/ratsd
%dir %{_libexecdir}/veraison-ratsd
%dir %{_libexecdir}/veraison-ratsd/plugins
%{_libexecdir}/veraison-ratsd/plugins/*.plugin
%dir %{_sysconfdir}/veraison-ratsd
%config(noreplace) %{_sysconfdir}/veraison-ratsd/config.yaml

%changelog
* Wed Aug 26 2026 Veraison Contributors <veraison@lists.trustedfirmware.org> - %{version}-%{release}
- Initial package
