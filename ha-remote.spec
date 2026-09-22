%global tag 0.1.2

Name:     ha-remote
Version:  %{tag}
Release:  1%{?dist}
Summary:  Control a niri laptop from Home Assistant and Apple Home

License:  MIT
URL:      https://github.com/lacamar/ha-remote
Source0:  %{url}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildArch: noarch

BuildRequires: python3-pywayland
BuildRequires: wayland-devel
BuildRequires: wayland-protocols-devel
BuildRequires: systemd-rpm-macros

Requires: python3-aiohttp
Requires: python3-pywayland
Requires: wtype
Requires: brightnessctl
Requires: playerctl
Requires: libsecret
Requires: libnotify
Requires: niri

%description
Agent that connects to Home Assistant over WebSocket and exposes the laptop as
switches, lights, a fan and sensors, with phone-approved typing of the login
password into sudo, polkit and the lock screen.

%prep
%autosetup

%build
mkdir -p protocols/hrproto
touch protocols/hrproto/__init__.py
python3 -m pywayland.scanner -o protocols/hrproto \
    -i %{_datadir}/wayland/wayland.xml \
    %{_datadir}/wayland-protocols/staging/ext-idle-notify/ext-idle-notify-v1.xml

%install
install -Dm755 ha-remote ha-remote-setup -t %{buildroot}%{_bindir}
install -Dm644 ha-remote.service -t %{buildroot}%{_userunitdir}
install -Dm644 config.example.toml -t %{buildroot}%{_datadir}/%{name}
cp -r protocols %{buildroot}%{_datadir}/%{name}/

%post
%systemd_user_post %{name}.service

%preun
%systemd_user_preun %{name}.service

%files
%license LICENSE
%doc README.md
%{_bindir}/ha-remote
%{_bindir}/ha-remote-setup
%{_userunitdir}/ha-remote.service
%{_datadir}/%{name}

%changelog
* Tue Sep 22 2026 Lachlan Marie <lchlnm@pm.me> - 0.1.2-1
- Tidier notification text

* Tue Sep 22 2026 Lachlan Marie <lchlnm@pm.me> - 0.1.1-1
- Ignore lingering polkit panel after typing

* Tue Sep 22 2026 Lachlan Marie <lchlnm@pm.me> - 0.1.0-1
- Initial package
