#!/bin/sh
# Install Pythia for this user: code under ~/.local/lib/pythia (so it runs at boot even when
# the source checkout lives on a disk that is mounted later), settings in ~/.config/pythia,
# and a systemd unit file ready for root to install. Run without sudo; it prints the few
# commands that need sudo.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
lib="$HOME/.local/lib/pythia"
conf="$HOME/.config/pythia/pythia.toml"
data="$HOME/.local/share/pythia"
state="$HOME/.local/state/pythia"

mkdir -p "$lib" "$data" "$state" "$(dirname "$conf")"
rm -rf "$lib/pythia"
cp -r "$here/pythia" "$lib/pythia"
find "$lib" -name __pycache__ -type d -prune -exec rm -rf {} +
if [ ! -e "$conf" ]; then
    cp "$here/pythia.example.toml" "$conf"
    echo "Created $conf: edit listen, allow_networks and home_gateway_mac."
fi
unit="$state/pythia.service"
sed -e "s#@USER@#$(id -un)#" -e "s#@LIB@#$lib#" -e "s#@CONFIG@#$conf#" \
    -e "s#@DATA@#$data#" -e "s#@STATE@#$state#" "$here/contrib/pythia.service.in" > "$unit"
PYTHONPATH="$lib" python3 -m pythia --config "$conf" update-lists || true

cat <<MSG

Code installed in $lib. Now, as root (once):

  sudo install -m 644 $unit /etc/systemd/system/pythia.service
  sudo systemctl daemon-reload
  sudo systemctl enable --now pythia
  sudo ufw allow from <your LAN, e.g. 192.168.1.0/24> to any port 53   # if ufw is on

Check:  dig @127.0.0.1 doubleclick.net +short    (0.0.0.0 means it works)
Dashboard: http://127.0.0.1:$(PYTHONPATH="$lib" python3 -c "from pythia import config; print(config.load(__import__('pathlib').Path('$conf')).web_port)")
To update the code later, run this script again and: sudo systemctl restart pythia
MSG
