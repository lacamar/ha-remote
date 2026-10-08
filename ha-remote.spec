%global tag 0.2.14

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
BuildRequires: python3-devel
BuildRequires: systemd-rpm-macros
%{?systemd_ordering}

Requires: python3-aiohttp
Requires: python3-pywayland
Requires: wtype
Requires: brightnessctl
Requires: playerctl
Requires: libsecret
Requires: niri
Requires: /usr/bin/noctalia
Requires: pam

%description
Agent that connects to Home Assistant over WebSocket and exposes the laptop as
switches, lights, a fan and sensors, with phone approval for sudo, polkit and
the lock screen.

%prep
%autosetup

%build
mkdir -p protocols/hrproto
touch protocols/hrproto/__init__.py
python3 -m pywayland.scanner -o protocols/hrproto \
    -i %{_datadir}/wayland/wayland.xml \
    %{_datadir}/wayland-protocols/staging/ext-idle-notify/ext-idle-notify-v1.xml

%install
install -Dm755 ha-remote ha-remote-setup ha-remote-auth -t %{buildroot}%{_bindir}
install -Dm755 pam-helper -t %{buildroot}%{_libexecdir}/%{name}
install -Dm644 haremote.py -t %{buildroot}%{python3_sitelib}
install -Dm644 ha-remote.service -t %{buildroot}%{_userunitdir}
install -Dm644 70-ha-remote-nuphy.rules -t %{buildroot}%{_udevrulesdir}
install -Dm644 ha-remote-auth.service -t %{buildroot}%{_unitdir}
install -Dm644 config.example.toml auth.example.toml -t %{buildroot}%{_datadir}/%{name}
install -dm700 %{buildroot}%{_sysconfdir}/%{name}
cp -r protocols %{buildroot}%{_datadir}/%{name}/

%post
%systemd_user_post %{name}.service
%systemd_post %{name}-auth.service
if [ $1 -gt 1 ] && grep -qs %{_libexecdir}/%{name}/pam-helper %{_sysconfdir}/pam.d/*; then
    %{_bindir}/ha-remote-auth enable >/dev/null || :
fi

%preun
%systemd_user_preun %{name}.service
%systemd_preun %{name}-auth.service
if [ $1 -eq 0 ]; then
    %{_bindir}/ha-remote-auth disable || :
fi

%postun
%systemd_user_postun_with_restart %{name}.service
%systemd_postun_with_restart %{name}-auth.service

%files
%license LICENSE
%doc README.md
%{_bindir}/ha-remote
%{_bindir}/ha-remote-setup
%{_bindir}/ha-remote-auth
%{_libexecdir}/%{name}/
%pycached %{python3_sitelib}/haremote.py
%{_userunitdir}/ha-remote.service
%{_udevrulesdir}/70-ha-remote-nuphy.rules
%{_unitdir}/ha-remote-auth.service
%dir %attr(0700,root,root) %{_sysconfdir}/%{name}
%{_datadir}/%{name}

%changelog
* Thu Oct 08 2026 Lachlan Marie <lchlnm@pm.me> - 0.2.14-1
- Fix lock screen re-asking after approval

* Wed Oct 07 2026 Lachlan Marie <lchlnm@pm.me> - 0.2.13-1
- Approve polkit text prompts
- Show the polkit caller's command

* Wed Oct 07 2026 Lachlan Marie <lchlnm@pm.me> - 0.2.12-1
- Approve sudo on a VT console

* Sun Oct 04 2026 Lachlan Marie <lchlnm@pm.me> - 0.2.11-1
- Approve polkit while locked
- Never type into the lock screen
- List all pending pkexec commands

* Sat Oct 03 2026 Lachlan Marie <lchlnm@pm.me> - 0.2.10-1
- Setup pairs the HomeKit lock
- NuPhy: skip the dongle

* Sat Oct 03 2026 Lachlan Marie <lchlnm@pm.me> - 0.2.9-1
- README: pairing the HomeKit lock

* Sat Oct 03 2026 Lachlan Marie <lchlnm@pm.me> - 0.2.8-1
- HomeKit lock replaces Lock/Unlock toggles
- Drop Pause music, music off covers it

* Fri Oct 02 2026 Lachlan Marie <lchlnm@pm.me> - 0.2.7-1
- Pause every MPRIS player, music off included
- Momentary controls back to input_boolean, reset at once

* Fri Oct 02 2026 Lachlan Marie <lchlnm@pm.me> - 0.2.6-1
- Pause music button
- README: NuPhy sync is wired only
- Lock screen input asks the phone

* Fri Oct 02 2026 Lachlan Marie <lchlnm@pm.me> - 0.2.5-1
- Mirror keyboard backlight to NuPhy keyboards
- udev access to NuPhy vendor HID interface
- Keyboard backlight via noctalia/UPower

* Fri Oct 02 2026 Lachlan Marie <lchlnm@pm.me> - 0.2.4-1
- Drop homekit_only option
- Drop 0.1 helper migration from setup
- Drop from-checkout protocol path
- Simplify job toggle and setup

* Wed Sep 30 2026 Lachlan Marie <lchlnm@pm.me> - 0.2.3-1
- No info line in the polkit panel

* Wed Sep 30 2026 Lachlan Marie <lchlnm@pm.me> - 0.2.2-1
- Phone approval alongside the open password prompt
- Empty lock screen submit asks the phone
- Refresh PAM lines on upgrade

* Wed Sep 30 2026 Lachlan Marie <lchlnm@pm.me> - 0.2.1-1
- Phone first for sudo and polkit, input cancels

* Wed Sep 30 2026 Lachlan Marie <lchlnm@pm.me> - 0.2.0-1
- Phone approval via PAM instead of typing the password
- Root ha-remote-auth service
- Momentary controls as input_button
- Unlock button
- Drop dashboard approve/deny and request sensor
- Fix hosts without battery or AC

* Wed Sep 30 2026 Lachlan Marie <lchlnm@pm.me> - 0.1.3-2
- Restart user service on upgrade
- Add systemd ordering

* Wed Sep 30 2026 Lachlan Marie <lchlnm@pm.me> - 0.1.3-1
- Clear password field before typing
- Desk plug automation keyed on presence
- Drop arrive reminder and desk plug automations from setup

* Tue Sep 22 2026 Lachlan Marie <lchlnm@pm.me> - 0.1.2-1
- Tidier notification text

* Tue Sep 22 2026 Lachlan Marie <lchlnm@pm.me> - 0.1.1-1
- Ignore lingering polkit panel after typing

* Tue Sep 22 2026 Lachlan Marie <lchlnm@pm.me> - 0.1.0-1
- Initial package
