#!/bin/bash

# ============================================
# Shimboot Setup Script
# ============================================
# Lives in /opt/setup/ (cloned from GitHub).
# Run: sudo setup [--status|--reset=1|--reset=2|--help]
# ============================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$SCRIPT_DIR"
CONF_FILE="$INSTALL_DIR/setup.conf"
STATUS_FILE="$INSTALL_DIR/status"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# ============================================
# Status Tracking
# ============================================
is_done() {
    [[ -f "$STATUS_FILE" ]] && grep -q "^$1=done$" "$STATUS_FILE" 2>/dev/null
}

mark_done() {
    echo "$1=done" >> "$STATUS_FILE"
    log_info "Completed: $1"
}

get_phase() {
    if is_done "phase1"; then echo "2"; else echo "1"; fi
}

show_status() {
    echo ""
    echo "========================================"
    echo "  Setup Status"
    echo "========================================"
    echo "Status file: $STATUS_FILE"
    echo ""
    if [[ -f "$STATUS_FILE" ]]; then
        echo "Completed steps:"
        sed 's/=done//' "$STATUS_FILE" | while read step; do
            echo "  [x] $step"
        done
    else
        echo "No steps completed yet"
    fi
    echo "========================================"
    echo ""
}

# ============================================
# Install command symlink
# ============================================
install_system_wide() {
    log_step "Setting up 'setup' command..."

    chmod +x "$INSTALL_DIR/setup.sh"

    # Create 'setup' command symlink
    ln -sf "$INSTALL_DIR/setup.sh" /usr/local/bin/setup

    # Remove old symlink if present
    rm -f /usr/local/bin/shimboot-setup

    # Create status file if needed
    [[ -f "$STATUS_FILE" ]] || touch "$STATUS_FILE"

    log_info "Command 'sudo setup' now available"
}

# ============================================
# Load config
# ============================================
load_config() {
    if [[ -f "$CONF_FILE" ]]; then
        source "$CONF_FILE"
        log_info "Loaded config from $CONF_FILE"
    else
        log_error "No config file found at $CONF_FILE"
        exit 1
    fi
}

# ============================================
# PHASE 1: Create new user, set hostname
# ============================================
phase1_create_user() {
    log_step "Creating new user '$NEW_USERNAME'..."

    if is_done "create_user"; then
        log_info "User creation already done, skipping"
        return
    fi

    if ! id "$NEW_USERNAME" &>/dev/null; then
        useradd -m -s /bin/bash "$NEW_USERNAME"
        echo "$NEW_USERNAME:$USER_PASSWORD" | chpasswd
        log_info "User $NEW_USERNAME created"
    else
        log_info "User $NEW_USERNAME already exists"
        echo "$NEW_USERNAME:$USER_PASSWORD" | chpasswd
    fi

    usermod -aG sudo "$NEW_USERNAME" 2>/dev/null || true
    usermod -aG wheel "$NEW_USERNAME" 2>/dev/null || true

    echo "$NEW_USERNAME ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$NEW_USERNAME"
    chmod 440 "/etc/sudoers.d/$NEW_USERNAME"

    log_info "User $NEW_USERNAME has admin privileges"
    mark_done "create_user"
}

phase1_set_hostname() {
    log_step "Setting hostname to '$HOSTNAME'..."

    if is_done "set_hostname"; then
        log_info "Hostname already set, skipping"
        return
    fi

    hostnamectl set-hostname "$HOSTNAME" 2>/dev/null || echo "$HOSTNAME" > /etc/hostname

    if grep -q "127.0.1.1" /etc/hosts; then
        sed -i "s/127.0.1.1.*/127.0.1.1\t$HOSTNAME/" /etc/hosts
    else
        echo "127.0.1.1	$HOSTNAME" >> /etc/hosts
    fi

    log_info "Hostname set to: $HOSTNAME"
    mark_done "set_hostname"
}

run_phase1() {
    echo ""
    echo "========================================"
    echo "  PHASE 1: Create User & Set Hostname"
    echo "========================================"
    echo ""

    phase1_create_user
    phase1_set_hostname

    mark_done "phase1"

    echo ""
    echo "========================================"
    log_info "Phase 1 complete!"
    echo "========================================"
    echo ""
    echo -e "${YELLOW}NEXT STEPS:${NC}"
    echo ""
    echo -e "  1. Reboot: ${GREEN}sudo reboot${NC}"
    echo ""
    echo -e "  2. Login as: ${GREEN}$NEW_USERNAME${NC}"
    echo -e "     Password: ${GREEN}$USER_PASSWORD${NC}"
    echo ""
    echo -e "  3. Run: ${GREEN}sudo setup${NC}"
    echo ""
    echo -e "${RED}DO NOT log back into '$OLD_USERNAME'${NC}"
    echo ""
}

# ============================================
# PHASE 2: Delete old user, install apps
# ============================================
phase2_check_user() {
    log_step "Checking current user..."

    local current_user=$(logname 2>/dev/null || echo "$SUDO_USER" || whoami)

    log_info "Current: $current_user | Expected: $NEW_USERNAME"

    if [[ "$current_user" == "$OLD_USERNAME" ]]; then
        log_error "Still logged in as '$OLD_USERNAME'!"
        echo "Log in as '$NEW_USERNAME' and run 'sudo setup' again"
        exit 1
    fi

    log_info "User check passed"
}

phase2_delete_old_user() {
    log_step "Deleting old user '$OLD_USERNAME'..."

    if is_done "delete_old_user"; then
        log_info "Already done, skipping"
        return
    fi

    if [[ "$OLD_USERNAME" == "$NEW_USERNAME" ]]; then
        log_info "Same user, skipping deletion"
        mark_done "delete_old_user"
        return
    fi

    if id "$OLD_USERNAME" &>/dev/null; then
        pkill -u "$OLD_USERNAME" 2>/dev/null || true
        sleep 2
        userdel -r "$OLD_USERNAME" 2>/dev/null || userdel "$OLD_USERNAME" 2>/dev/null || true
        rm -f "/etc/sudoers.d/$OLD_USERNAME" 2>/dev/null || true
        rm -rf "/home/$OLD_USERNAME" 2>/dev/null || true
        log_info "Old user deleted"
    else
        log_info "Old user doesn't exist"
    fi

    mark_done "delete_old_user"
}

phase2_remove_bloat() {
    log_step "Removing bloat..."

    if is_done "remove_bloat"; then
        log_info "Already done, skipping"
        return
    fi

    # Disable shimboot apt repo — packages are baked into image, repo is
    # unreliable and causes 5+ minute hangs on every apt operation
    if [[ -f /etc/apt/sources.list ]]; then
        sed -i '/shimboot\.ading\.dev/s/^/#/' /etc/apt/sources.list
        log_info "Disabled shimboot.ading.dev apt repo (unreliable)"
    fi

    if command -v apt &>/dev/null; then
        apt remove -y plasma-discover discover gnome-software flatpak snapd \
            kwalletmanager 2>/dev/null || true
        dpkg --remove --force-remove-reinstreq plasma-discover 2>/dev/null || true
        apt autoremove -y 2>/dev/null || true
        log_info "Bloat removed"
    fi

    mark_done "remove_bloat"
}

phase2_install_deps() {
    log_step "Installing dependencies..."

    if is_done "install_deps"; then
        log_info "Already done, skipping"
        return
    fi

    apt update
    apt install -y curl wget apt-transport-https gnupg ca-certificates unzip libnss3-tools iptables xdotool inotify-tools
    log_info "Dependencies installed"

    mark_done "install_deps"
}

phase2_install_brave() {
    log_step "Installing Brave..."

    if is_done "install_brave"; then
        log_info "Already done, skipping"
        return
    fi

    curl -fsSLo /usr/share/keyrings/brave-browser-archive-keyring.gpg \
        https://brave-browser-apt-release.s3.brave.com/brave-browser-archive-keyring.gpg

    echo "deb [signed-by=/usr/share/keyrings/brave-browser-archive-keyring.gpg] https://brave-browser-apt-release.s3.brave.com/ stable main" \
        > /etc/apt/sources.list.d/brave-browser-release.list

    apt update
    apt install -y brave-browser

    if command -v brave-browser &>/dev/null; then
        apt remove -y firefox firefox-esr 2>/dev/null || true
        sudo -u "$NEW_USERNAME" xdg-settings set default-web-browser brave-browser.desktop 2>/dev/null || true
        log_info "Brave installed"
    fi

    mark_done "install_brave"
}

phase2_install_vscode() {
    log_step "Installing VS Code..."

    if is_done "install_vscode"; then
        log_info "Already done, skipping"
        return
    fi

    curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft.gpg
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/code stable main" \
        > /etc/apt/sources.list.d/vscode.list

    apt update
    apt install -y code
    log_info "VS Code installed"

    mark_done "install_vscode"
}

phase2_install_chrome() {
    log_step "Installing Google Chrome..."

    if is_done "install_chrome"; then
        if command -v google-chrome &>/dev/null; then
            log_info "Already done, skipping"
            return
        fi
    fi

    curl -fsSL https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb/ stable main" \
        > /etc/apt/sources.list.d/google-chrome.list

    apt update
    apt install -y google-chrome-stable
    log_info "Chrome installed"

    mark_done "install_chrome"
}

phase2_install_tailscale() {
    log_step "Installing Tailscale..."

    if is_done "install_tailscale"; then
        log_info "Already done, skipping"
        return
    fi

    curl -fsSL https://tailscale.com/install.sh | sh
    systemctl enable --now tailscaled 2>/dev/null || true
    sleep 2

    # Logout first in case already authenticated
    tailscale logout 2>/dev/null || true
    sleep 1

    if [[ -n "$TAILSCALE_AUTHKEY" ]]; then
        log_info "Authenticating with auth key..."
        tailscale up --reset --force-reauth --authkey="$TAILSCALE_AUTHKEY" --hostname="$HOSTNAME"
    else
        echo ""
        echo "No TAILSCALE_AUTHKEY set. Run manually:"
        echo "  sudo tailscale logout"
        echo "  sudo tailscale up --hostname=$HOSTNAME"
        echo ""
    fi

    log_info "Tailscale installed"
    mark_done "install_tailscale"
}

phase2_setup_vpn() {
    log_step "Setting up VPN scripts..."

    if is_done "setup_vpn" && [[ -x "/usr/local/bin/vpn-on" ]]; then
        log_info "Already done, skipping"
        return
    fi

    cat > /usr/local/bin/vpn-on << 'EOF'
#!/bin/bash
source /opt/setup/setup.conf
[[ -z "$TAILSCALE_EXIT_NODE" ]] && { echo "TAILSCALE_EXIT_NODE not set"; exit 1; }
echo "Connecting to: $TAILSCALE_EXIT_NODE"
sudo bash -c 'echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" > /etc/resolv.conf'
sudo tailscale up --exit-node="$TAILSCALE_EXIT_NODE" --accept-dns=false --accept-routes --hostname="$HOSTNAME"
echo "Connected!"
EOF

    cat > /usr/local/bin/vpn-off << 'EOF'
#!/bin/bash
echo "Disconnecting..."
sudo tailscale up --exit-node= --accept-dns=false
sudo systemctl restart systemd-resolved 2>/dev/null || true
echo "Disconnected"
EOF

    chmod +x /usr/local/bin/vpn-on /usr/local/bin/vpn-off

    cat > /etc/systemd/system/tailscale-vpn.service << 'EOF'
[Unit]
Description=Tailscale VPN Exit Node
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/vpn-on
ExecStop=/usr/local/bin/vpn-off

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_info "VPN scripts created"
    mark_done "setup_vpn"
}

phase2_setup_chrome_netns() {
    log_step "Setting up Chrome network namespace..."

    if is_done "setup_chrome_netns" && [[ -x "/usr/local/bin/chrome-netns-setup.sh" ]]; then
        log_info "Already done, skipping"
        return
    fi

    local user_home="/home/$NEW_USERNAME"
    local PHYS_IF=$(ip route | grep default | grep -v tailscale | awk '{print $5}' | head -1)
    [[ -z "$PHYS_IF" ]] && PHYS_IF=$(ip route | grep default | awk '{print $5}' | head -1)
    local DNS=$(nmcli dev show "$PHYS_IF" 2>/dev/null | grep DNS | awk '{print $2}' | head -2 | tr '\n' ',' | sed 's/,$//')
    [[ -z "$DNS" ]] && DNS="1.1.1.1,8.8.8.8"

    log_info "Interface: $PHYS_IF | DNS: $DNS"

    # Create namespace setup script
    cat > /usr/local/bin/chrome-netns-setup.sh << SETUPEOF
#!/bin/bash
set -e
NAMESPACE="chrome_ns"
PHYS_IF="$PHYS_IF"
VETH_HOST="veth-host"
VETH_NS="veth-chrome"
NS_SUBNET="10.200.1"
IPT="iptables-legacy"

modprobe veth iptable_nat nf_nat xt_MASQUERADE 2>/dev/null || true

ip netns del "\$NAMESPACE" 2>/dev/null || true
ip link del "\$VETH_HOST" 2>/dev/null || true
for p in 5199 5200; do
    ip rule del to "\${NS_SUBNET}.0/24" lookup main priority \$p 2>/dev/null || true
    ip rule del from "\${NS_SUBNET}.0/24" lookup main priority \$p 2>/dev/null || true
done
ip rule del iif "\$VETH_HOST" lookup main priority 5199 2>/dev/null || true

ip netns add "\$NAMESPACE"
ip link add "\$VETH_HOST" type veth peer name "\$VETH_NS"
ip link set "\$VETH_NS" netns "\$NAMESPACE"
ip addr add "\${NS_SUBNET}.1/24" dev "\$VETH_HOST"
ip link set "\$VETH_HOST" up

ip netns exec "\$NAMESPACE" ip addr add "\${NS_SUBNET}.2/24" dev "\$VETH_NS"
ip netns exec "\$NAMESPACE" ip link set "\$VETH_NS" up
ip netns exec "\$NAMESPACE" ip link set lo up
ip netns exec "\$NAMESPACE" ip route add default via "\${NS_SUBNET}.1"

sysctl -w net.ipv4.ip_forward=1 > /dev/null
ip rule add to "\${NS_SUBNET}.0/24" lookup main priority 5200
ip rule add from "\${NS_SUBNET}.0/24" lookup main priority 5200
ip rule add iif "\$VETH_HOST" lookup main priority 5199

\$IPT -t nat -D POSTROUTING -s "\${NS_SUBNET}.0/24" -o "\$PHYS_IF" -j MASQUERADE 2>/dev/null || true
\$IPT -D FORWARD -i "\$VETH_HOST" -o "\$PHYS_IF" -j ACCEPT 2>/dev/null || true
\$IPT -D FORWARD -i "\$PHYS_IF" -o "\$VETH_HOST" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

\$IPT -t nat -A POSTROUTING -s "\${NS_SUBNET}.0/24" -o "\$PHYS_IF" -j MASQUERADE
\$IPT -A FORWARD -i "\$VETH_HOST" -o "\$PHYS_IF" -j ACCEPT
\$IPT -A FORWARD -i "\$PHYS_IF" -o "\$VETH_HOST" -m state --state RELATED,ESTABLISHED -j ACCEPT

# Waydroid bridge: only keep TO rule so return packets reach the bridge.
# Outbound waydroid traffic falls through to Tailscale's table 52 (VPN).
WD_SUBNET="192.168.240"
ip rule del to "\${WD_SUBNET}.0/24" lookup main priority 5200 2>/dev/null || true
ip rule add to "\${WD_SUBNET}.0/24" lookup main priority 5200

echo "Chrome namespace ready: \${NS_SUBNET}.2 via \$PHYS_IF"
echo "Waydroid bridge rule added: TO \${WD_SUBNET}.0/24 via main table"
SETUPEOF
    chmod +x /usr/local/bin/chrome-netns-setup.sh

    # Systemd service
    cat > /etc/systemd/system/chrome-netns.service << 'EOF'
[Unit]
Description=Chrome Network Namespace (VPN bypass)
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/chrome-netns-setup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    # DNS config - school DNS first (always), then auto-detected, then public fallback
    # School DNS is required for on-prem detection even when setup runs off-campus
    mkdir -p /etc/netns/chrome_ns
    : > /etc/netns/chrome_ns/resolv.conf
    # 1. School DNS (from config) - always first for on-prem detection
    if [[ -n "${SCHOOL_DNS:-}" ]]; then
        echo "$SCHOOL_DNS" | tr ',' '\n' | while read -r ns; do
            [[ -n "$ns" ]] && echo "nameserver $ns"
        done >> /etc/netns/chrome_ns/resolv.conf
    fi
    # 2. Auto-detected DNS (current network) - useful if different from school
    if [[ -n "$DNS" && "$DNS" != "1.1.1.1,8.8.8.8" ]]; then
        echo "$DNS" | tr ',' '\n' | while read -r ns; do
            [[ -n "$ns" ]] && ! grep -q "$ns" /etc/netns/chrome_ns/resolv.conf && echo "nameserver $ns"
        done >> /etc/netns/chrome_ns/resolv.conf
    fi
    # 3. Public DNS fallback (off-campus / home network)
    grep -q "8.8.8.8" /etc/netns/chrome_ns/resolv.conf || echo "nameserver 8.8.8.8" >> /etc/netns/chrome_ns/resolv.conf
    grep -q "1.1.1.1" /etc/netns/chrome_ns/resolv.conf || echo "nameserver 1.1.1.1" >> /etc/netns/chrome_ns/resolv.conf

    # Kernel modules
    echo -e "veth\niptable_nat\nnf_nat\nxt_MASQUERADE" > /etc/modules-load.d/chrome-netns.conf

    # Sudoers
    echo "$NEW_USERNAME ALL=(root) NOPASSWD: /usr/sbin/ip netns exec chrome_ns *" > /etc/sudoers.d/chrome-netns
    chmod 440 /etc/sudoers.d/chrome-netns

    systemctl daemon-reload
    systemctl enable chrome-netns.service
    systemctl start chrome-netns.service 2>/dev/null || log_warn "Start failed, reboot required"

    log_info "Chrome namespace configured"
    mark_done "setup_chrome_netns"
}

phase2_setup_chrome_certs() {
    log_step "Installing SSL certificates..."

    local user_home="/home/$NEW_USERNAME"
    local nssdb_dir="$user_home/.pki/nssdb"
    local certs_dir="$INSTALL_DIR/certs"
    local policy_file="/etc/opt/chrome/policies/managed/managed-extensions.json"

    # Install certs from folder (only if certs exist)
    # Check each extension separately - ls fails if ANY glob doesn't match
    local has_certs=false
    if [[ -d "$certs_dir" ]]; then
        for ext in pem crt cer; do
            ls "$certs_dir"/*."$ext" &>/dev/null && has_certs=true && break
        done
    fi

    if [[ "$has_certs" == "true" ]]; then
        # Create NSS database only when we have certs to install
        if [[ ! -f "$nssdb_dir/cert9.db" ]]; then
            rm -rf "$nssdb_dir"
            mkdir -p "$nssdb_dir"
            chown "$NEW_USERNAME:$NEW_USERNAME" "$nssdb_dir"
            printf '\n\n' | sudo -u "$NEW_USERNAME" certutil -d "sql:$nssdb_dir" -N 2>/dev/null || true
            log_info "NSS database created"
        fi

        # Split multi-cert PEM files and import each cert individually
        # (certutil -A only imports the first cert from a multi-cert PEM)
        # trusted_certs → "C,," (trusted CA for SSL)
        # distrusted_certs → "p,p,p" (explicitly distrusted)
        local cert_count=0
        local distrust_count=0
        local tmpdir=$(mktemp -d)
        chmod 755 "$tmpdir"  # certutil runs as user, needs read access
        for cert_file in "$certs_dir"/*.pem "$certs_dir"/*.crt "$certs_dir"/*.cer; do
            [[ -f "$cert_file" ]] || continue
            local base_name=$(basename "$cert_file" | sed 's/\.[^.]*$//')

            # Determine trust level from filename
            local trust_flags="C,,"
            if [[ "$base_name" == *distrusted* ]]; then
                trust_flags="p,p,p"
            fi

            # Split into individual certs
            csplit -z -f "$tmpdir/${base_name}_" -b '%02d.pem' "$cert_file" '/-----BEGIN CERTIFICATE-----/' '{*}' 2>/dev/null || true
            chmod 644 "$tmpdir"/*.pem 2>/dev/null || true

            for single_cert in "$tmpdir/${base_name}_"*.pem; do
                [[ -f "$single_cert" ]] || continue
                # Skip empty fragments
                grep -q "BEGIN CERTIFICATE" "$single_cert" || continue
                local cert_name="${base_name}_${cert_count}"
                log_info "Installing cert: $cert_name (trust: $trust_flags)"

                sudo -u "$NEW_USERNAME" certutil -d "sql:$nssdb_dir" -D -n "$cert_name" 2>/dev/null || true
                if ! sudo -u "$NEW_USERNAME" certutil -d "sql:$nssdb_dir" -A -t "$trust_flags" -n "$cert_name" -i "$single_cert"; then
                    log_warn "Failed to install cert $cert_name into NSS"
                fi

                # Only add trusted certs to system CA store
                if [[ "$trust_flags" == "C,," ]]; then
                    cp "$single_cert" "/usr/local/share/ca-certificates/${cert_name}.crt" 2>/dev/null || true
                    cert_count=$((cert_count + 1))
                else
                    distrust_count=$((distrust_count + 1))
                fi
            done
        done
        rm -rf "$tmpdir"
        update-ca-certificates 2>/dev/null || true
        log_info "Installed $cert_count trusted + $distrust_count distrusted certificate(s) into NSS"

        # Inject CACertificates into Chrome enterprise policy
        # Only inject trusted certs (not distrusted ones)
        mkdir -p "$(dirname "$policy_file")"
        if [[ ! -f "$policy_file" ]]; then
            echo '{}' > "$policy_file"
        fi
        python3 << PYEOF
import json, glob, os

certs_dir = '$certs_dir'
# Only inject trusted certs into Chrome policy (skip distrusted)
skip_patterns = {'distrusted'}

pem_certs = []
for ext in ('*.pem', '*.crt', '*.cer'):
    for cert_file in sorted(glob.glob(os.path.join(certs_dir, ext))):
        basename = os.path.basename(cert_file)
        if any(p in basename for p in skip_patterns):
            print(f'Skipping {basename} (distrusted)')
            continue
        with open(cert_file, 'r') as f:
            content = f.read()
        current = []
        in_cert = False
        for line in content.strip().split('\n'):
            if line.startswith('-----BEGIN CERTIFICATE-----'):
                in_cert = True
                current = [line]
            elif line.startswith('-----END CERTIFICATE-----'):
                current.append(line)
                pem_certs.append('\n'.join(current))
                in_cert = False
            elif in_cert:
                current.append(line)

# Deduplicate
seen = set()
unique_certs = []
for c in pem_certs:
    if c not in seen:
        seen.add(c)
        unique_certs.append(c)

with open('$policy_file', 'r') as f:
    policy = json.load(f)
policy['CACertificates'] = unique_certs
with open('$policy_file', 'w') as f:
    json.dump(policy, f, indent=4)
    f.write('\n')
print(f'Injected {len(unique_certs)} CA certificate(s) into Chrome policy')
PYEOF
        # Update backup copy
        cp "$policy_file" /opt/chrome-direct/policies/ 2>/dev/null || true
    else
        log_info "No certs found, skipping (Chrome will create NSS db on first run)"
    fi

    # Helper script
    cat > /usr/local/bin/install-ssl-cert << 'EOF'
#!/bin/bash
[[ -z "$1" || ! -f "$1" ]] && { echo "Usage: $0 cert.pem [name]"; exit 1; }
CERT="$1"; NAME="${2:-$(basename "$1" | sed 's/\.[^.]*$//')}"
[[ ! -d "$HOME/.pki/nssdb" ]] && { mkdir -p "$HOME/.pki/nssdb"; printf '\n\n' | certutil -d sql:$HOME/.pki/nssdb -N; }
certutil -d sql:$HOME/.pki/nssdb -D -n "$NAME" 2>/dev/null || true
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "$NAME" -i "$CERT"
echo "Installed: $NAME. Restart Chrome."
EOF
    chmod +x /usr/local/bin/install-ssl-cert
}

phase2_setup_chrome_extensions() {
    log_step "Installing Chrome extensions (chrome-direct)..."

    local user_home="/home/$NEW_USERNAME"
    local ext_src="$INSTALL_DIR/extensions"
    local ext_dest="/opt/chrome-extensions"
    local policy_dir="/etc/opt/chrome/policies/managed"
    local patched_dir="/opt/chrome-direct/patched-extensions"

    # Copy local unpacked extensions to /opt if they exist
    mkdir -p "$ext_dest"
    if [[ -d "$ext_src" ]]; then
        cp -r "$ext_src"/* "$ext_dest/" 2>/dev/null || true
        log_info "Copied local extensions to $ext_dest"
    fi

    # =============================================
    # Chrome Policy: Force-install ALL extensions
    # =============================================
    # Extensions are force-installed via policy (except Eduphoria).
    # Eduphoria is loaded as an unpacked extension with env set to "dev"
    # to bypass ChromeOS platform checks. It can't be force-installed because
    # Chrome's integrity verification re-downloads patched files.
    # StudentKeeper JS files are patched in-place before each launch.

    mkdir -p "$policy_dir"

    log_info "Creating Chrome extension policy..."

    cat > "$policy_dir/managed-extensions.json" << 'EOF'
{
    "ExtensionInstallForcelist": [
        "haldlgldplgnggkjaafhelgiaglafanh;https://ext.goguardian.com/stable.xml",
        "bfijnabjihmoknklklebejaljjfdnlmo;https://ticketmaster.goguardian.com/update",
        "johiffgefcnfiddcakohlcpebgpidnji;https://cdn.imp.contentkeeper.net/clients/production/chrome/update-manifest.xml",
        "idcfmfbkmhjnnkfdhcckcoopllbmhnmg;https://clients2.google.com/service/update2/crx",
        "ecimfebadcfiablhgjpheinknpdkdjhh;https://clients2.google.com/service/update2/crx",
        "ihidolefpgnimlmgfljonacidpkmbhcl;https://clients2.google.com/service/update2/crx",
        "jgfbgkjjlonelmpenhpfeeljjlcgnkpe;https://clients2.google.com/service/update2/crx",
        "iaigceaehdihlnolehbapjfbbfpnlngg;https://clients2.google.com/service/update2/crx",
        "inoeonmfapjbbkmdafoankkfajkcphgd;https://clients2.google.com/service/update2/crx",
        "eefedolmcildfckjamddopaplfiiankl;https://clients2.google.com/service/update2/crx",
        "enfolipbjmnmleonhhebhalojdpcpdoo;https://clients2.google.com/service/update2/crx"
    ],
    "ExtensionInstallAllowlist": ["*"],
    "DeveloperToolsAvailability": 1,
    "ExtensionInstallBlocklist": [],
    "BlockExternalExtensions": false,
    "DnsOverHttpsMode": "off",
    "3rdparty": {
        "extensions": {
            "johiffgefcnfiddcakohlcpebgpidnji": {
                "ckAuth": true
            }
        }
    }
}
EOF

    # Inject CACertificates into the policy immediately so the file is always complete.
    # This prevents cert loss if phase2_setup_chrome_certs is skipped or fails.
    local certs_src="$INSTALL_DIR/certs"
    if [[ -d "$certs_src" ]]; then
        python3 << CERTEOF
import json, glob, os

certs_dir = '$certs_src'
policy_file = '$policy_dir/managed-extensions.json'
skip_patterns = {'distrusted'}

pem_certs = []
for ext in ('*.pem', '*.crt', '*.cer'):
    for cert_file in sorted(glob.glob(os.path.join(certs_dir, ext))):
        basename = os.path.basename(cert_file)
        if any(p in basename for p in skip_patterns):
            continue
        with open(cert_file, 'r') as f:
            content = f.read()
        current = []
        in_cert = False
        for line in content.strip().split('\n'):
            if line.startswith('-----BEGIN CERTIFICATE-----'):
                in_cert = True
                current = [line]
            elif line.startswith('-----END CERTIFICATE-----'):
                current.append(line)
                pem_certs.append('\n'.join(current))
                in_cert = False
            elif in_cert:
                current.append(line)

# Deduplicate
seen = set()
unique_certs = []
for c in pem_certs:
    if c not in seen:
        seen.add(c)
        unique_certs.append(c)

if unique_certs:
    with open(policy_file, 'r') as f:
        policy = json.load(f)
    policy['CACertificates'] = unique_certs
    with open(policy_file, 'w') as f:
        json.dump(policy, f, indent=4)
        f.write('\n')
    print(f'Injected {len(unique_certs)} CA certificate(s) into Chrome policy')
CERTEOF
    fi

    # Also store a backup copy
    mkdir -p /opt/chrome-direct/policies
    cp "$policy_dir/managed-extensions.json" /opt/chrome-direct/policies/

    log_info "Policy installed (11 force-installed extensions)"
    log_info "  - GoGuardian + GoGuardian License (enterprise)"
    log_info "  - StudentKeeper (patched for ChromeOS in-place)"
    log_info "  - Eduphoria LockDown (unpacked, dev mode bypass)"
    log_info "  - DnsOverHttpsMode=off (forces school DNS for on-prem detection)"
    log_info "  - CKAuth=true (StudentKeeper on-prem via ContentKeeper auth)"

    # =============================================
    # Eduphoria: Pre-patched unpacked extension (dev mode bypass)
    # =============================================
    # Eduphoria can't be force-installed because Chrome's integrity
    # verification re-downloads patched files. Instead we ship a
    # pre-patched copy with env:"dev" which bypasses all platform checks.
    if [[ -d "$ext_src/eduphoria" ]]; then
        cp -r "$ext_src/eduphoria" /opt/chrome-direct/eduphoria
        chown -R "$NEW_USERNAME:$NEW_USERNAME" /opt/chrome-direct/eduphoria
        chmod -R a+r /opt/chrome-direct/eduphoria
        find /opt/chrome-direct/eduphoria -type d -exec chmod a+rx {} \;
        log_info "Eduphoria unpacked extension installed to /opt/chrome-direct/eduphoria"
        log_info "  Load via chrome://extensions → Developer mode → Load unpacked"
    fi

    # =============================================
    # Extension patching script (runs before each launch)
    # =============================================
    _create_extension_patch_script

    # =============================================
    # ChromeOS User-Agent + chrome-direct launcher
    # =============================================
    local chrome_version
    chrome_version=$(google-chrome --version 2>/dev/null | grep -oP '[\d.]+' | head -1)
    [[ -z "$chrome_version" ]] && chrome_version="130.0.6723.116"
    local cros_ua="Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chrome_version} Safari/537.36"

    # Create keep-active daemon (prevents GoGuardian idle detection)
    cat > /opt/chrome-direct/keep-active.sh << 'KEEPEOF'
#!/bin/bash
# Keeps Chrome "active" for GoGuardian by sending periodic synthetic input
# to the Chrome Xwayland window. This prevents chrome.idle from reporting
# idle state without affecting the user's actual workflow.
#
# How it works:
# - Every 30 seconds, sends a synthetic mouse wiggle to Chrome's X11 window
# - Uses xdotool --window to target Chrome specifically (no focus steal)
# - Chrome sees input events and reports "active" to extensions
# - User can work in any other app uninterrupted

DISPLAY=:1
export DISPLAY

INTERVAL=30  # seconds between pings

while true; do
    # Find Chrome window (re-check each cycle in case window ID changes)
    CHROME_WID=$(xdotool search --class "Google-chrome" 2>/dev/null | head -1)

    if [ -n "$CHROME_WID" ]; then
        # Send synthetic mouse movement within Chrome's window
        # This resets Chrome's internal idle timer without stealing focus
        xdotool mousemove --window "$CHROME_WID" 100 100 2>/dev/null
        xdotool mousemove --window "$CHROME_WID" 101 101 2>/dev/null
    fi

    sleep "$INTERVAL"
done
KEEPEOF
    chmod +x /opt/chrome-direct/keep-active.sh
    log_info "keep-active.sh daemon created"

    # Create the filesystem watcher (event-driven patching via inotifywait)
    cat > /opt/chrome-direct/watch-and-patch.sh << WATCHEOF
#!/bin/bash
# Watches Chrome extension directories for new/modified files and patches
# immediately. Event-driven via inotifywait instead of timer-based polling.

PROFILE="$user_home/.config/chrome-direct/Default/Extensions"
PATCH_SCRIPT="/opt/chrome-direct/patch-extensions.sh"

LAST_PATCH=0
DEBOUNCE=5

do_patch() {
    local now=\$(date +%s)
    local elapsed=\$((now - LAST_PATCH))
    if [[ \$elapsed -ge \$DEBOUNCE ]]; then
        \$PATCH_SCRIPT 2>/dev/null
        LAST_PATCH=\$(date +%s)
    fi
}

do_patch

while [[ ! -d "\$PROFILE" ]]; do sleep 2; done

inotifywait -m -r -q \\
    --include '\\.(js)\$' \\
    -e create -e moved_to \\
    "\$PROFILE" 2>/dev/null | while read dir event file; do
        case "\$dir" in
            *haldlgldplgnggkjaafhelgiaglafanh*|*johiffgefcnfiddcakohlcpebgpidnji*)
                do_patch
                ;;
        esac
    done
WATCHEOF
    chmod +x /opt/chrome-direct/watch-and-patch.sh

    # Create chrome-direct launcher script
    cat > /usr/local/bin/chrome-direct << EOF
#!/bin/bash
# Chrome Direct - Launches Chrome in the direct network namespace (bypasses VPN)
# ChromeOS spoofing via User-Agent + in-place extension patching

# Pre-launch: register unpacked Eduphoria extension in Preferences
python3 /opt/chrome-direct/inject-unpacked.py 2>/dev/null || true

# Pre-launch patch: patches existing extension files from previous session
sudo /opt/chrome-direct/patch-extensions.sh 2>/dev/null || true

# Launch Chrome in the network namespace (background)
sudo /usr/sbin/ip netns exec chrome_ns sudo -u $NEW_USERNAME /usr/bin/google-chrome \\
    --user-data-dir=$user_home/.config/chrome-direct \\
    --no-first-run \\
    --user-agent="$cros_ua" \\
    --extension-content-verification=none \\
    "\$@" &
CHROME_PID=\$!

# Filesystem watcher: patches extensions instantly when Chrome creates new files
sudo /opt/chrome-direct/watch-and-patch.sh &
WATCH_PID=\$!

# Start the keep-active daemon (prevents GoGuardian idle detection)
/opt/chrome-direct/keep-active.sh &
KEEPALIVE_PID=\$!

# Wait for Chrome to exit
wait \$CHROME_PID 2>/dev/null

# Clean up
kill "\$KEEPALIVE_PID" "\$WATCH_PID" 2>/dev/null
pkill -f "inotifywait.*chrome-direct" 2>/dev/null
EOF
    chmod +x /usr/local/bin/chrome-direct

    # Desktop launcher
    mkdir -p "$user_home/.local/share/applications"
    cat > "$user_home/.local/share/applications/chrome-direct.desktop" << EOF
[Desktop Entry]
Name=Chrome (Direct Network)
Comment=Chrome browser bypassing Tailscale VPN (ChromeOS spoofed)
Exec=sudo /usr/local/bin/chrome-direct
Type=Application
Terminal=false
Icon=google-chrome
Categories=Network;WebBrowser;
StartupWMClass=Google-chrome
EOF
    chown "$NEW_USERNAME:$NEW_USERNAME" "$user_home/.local/share/applications/chrome-direct.desktop"

    log_info "chrome-direct launcher created with ChromeOS spoofing"
}

# Helper: Create the pre-launch extension patching script
_create_extension_patch_script() {
    local user_home="/home/$NEW_USERNAME"

    mkdir -p /opt/chrome-direct

    # Create the rehash helper (recomputes computed_hashes.json after patching
    # so Chrome doesn't detect modifications and trigger repair re-downloads)
    cat > /opt/chrome-direct/rehash-extension.py << 'REHASHEOF'
#!/usr/bin/env python3
"""Recompute computed_hashes.json for a Chrome extension version directory.
Only updates computed_hashes.json - does NOT touch verified_contents.json
(Chrome treats a missing verified_contents.json as corruption)."""
import hashlib, base64, json, os, sys

ver_dir = sys.argv[1]
metadata_dir = os.path.join(ver_dir, '_metadata')
ch_path = os.path.join(metadata_dir, 'computed_hashes.json')

if not os.path.exists(ch_path):
    sys.exit(0)

with open(ch_path) as f:
    data = json.load(f)

changed = False
for entry in data.get('file_hashes', []):
    filepath = os.path.join(ver_dir, entry['path'])
    if not os.path.isfile(filepath):
        continue
    block_size = entry.get('block_size', 4096)
    new_hashes = []
    with open(filepath, 'rb') as f:
        while True:
            block = f.read(block_size)
            if not block:
                break
            h = hashlib.sha256(block).digest()
            new_hashes.append(base64.b64encode(h).decode('ascii'))
    if new_hashes != entry['block_hashes']:
        entry['block_hashes'] = new_hashes
        changed = True

if changed:
    with open(ch_path, 'w') as f:
        json.dump(data, f, separators=(',', ':'))
    name = os.path.basename(ver_dir.rstrip('/'))
    print(f'  Hashes updated: {name}')
REHASHEOF
    chmod +x /opt/chrome-direct/rehash-extension.py

    cat > /opt/chrome-direct/patch-extensions.sh << PATCHEOF
#!/bin/bash
# Patch extension files within the Chrome profile before launch.
# After patching, recomputes _metadata/computed_hashes.json so Chrome
# doesn't detect modification and trigger a repair re-download.

PROFILE="$user_home/.config/chrome-direct/Default/Extensions"
REHASH="/opt/chrome-direct/rehash-extension.py"

# --- GoGuardian: Disable window focus + idle detection ---
GG_DIR="\$PROFILE/haldlgldplgnggkjaafhelgiaglafanh"
if [[ -d "\$GG_DIR" ]]; then
    for ver_dir in "\$GG_DIR"/*/; do
        bg="\$ver_dir/background.js"
        [[ -f "\$bg" ]] || continue
        python3 -c "
with open('\$bg','r') as f: c=f.read()
o=c
c=c.replace('e.idleManager.isFarmerConnected?{idleState:\"active\"','true?{idleState:\"active\"')
c=c.replace('chrome.windows.onFocusChanged.addListener(t)','chrome.windows.onFocusChanged.addListener(()=>{})')
c=c.replace('chrome.windows.onFocusChanged.addListener(n)','chrome.windows.onFocusChanged.addListener(()=>{})')
c=c.replace('idle.onStateChanged.addListener((async t=>{(await e).dispatch(d({idleState:t,','idle.onStateChanged.addListener((async t=>{(await e).dispatch(d({idleState:\"active\",')
if c!=o:
    with open('\$bg','w') as f: f.write(c)
    print('GoGuardian: patched')
else:
    print('GoGuardian: already patched or patterns changed')
" 2>/dev/null || true
        python3 "\$REHASH" "\$ver_dir" 2>/dev/null
    done
fi

# --- StudentKeeper: Force isChromeOS=true + bypass all ChromeOS gates ---
SK_DIR="\$PROFILE/johiffgefcnfiddcakohlcpebgpidnji"
if [[ -d "\$SK_DIR" ]]; then
    for ver_dir in "\$SK_DIR"/*/; do
        sw="\$ver_dir/js/serviceWorker.js"
        pp="\$ver_dir/js/popup.js"

        for jsfile in "\$sw" "\$pp"; do
            [[ -f "\$jsfile" ]] || continue
            python3 << PYEOF
with open('\$jsfile','r') as f: c=f.read()
o=c

# Patch: initialize() call - force isChromeOS=true
c=c.replace('"cros"===t.os||e)', '"cros"===t.os||e||!0)')

# Patch: isFilteringEnabled + all isChromeOS guards
for var in 'EkCSxwbATRIOPNDF_':
    v = var
    old_filt = 'if(!%s.runningConfig.device.isChromeOS)return!1' % v
    if old_filt in c:
        c = c.replace(old_filt, 'if(!1)return!1')
    old_and = '&&%s.runningConfig.device.isChromeOS' % v
    if old_and in c:
        c = c.replace(old_and, '&&!0')
    old_if = 'if(!%s.runningConfig.device.isChromeOS){' % v
    if old_if in c:
        c = c.replace(old_if, 'if(!1){')
    old_plat = '"cros"===e.os&&(%s.runningConfig.device.platformName="ChromeOS")' % v
    if old_plat in c:
        c = c.replace(old_plat, '(%s.runningConfig.device.platformName="ChromeOS")' % v)

if c!=o:
    with open('\$jsfile','w') as f: f.write(c)
    print('StudentKeeper %s: patched' % '\$jsfile'.split('/')[-1])
else:
    print('StudentKeeper %s: already patched or patterns changed' % '\$jsfile'.split('/')[-1])
PYEOF
        done
        python3 "\$REHASH" "\$ver_dir" 2>/dev/null
    done
fi

# --- Eduphoria LockDown Browser: Enable dev mode to bypass platform checks ---
# Every platform check has a built-in dev bypass: "dev"===s.env
# Changing env from "prod" to "dev" makes all 6 checks pass at once.
ED_DIR="\$PROFILE/egbobbmkefefhmoddnnpfgomegoccgoe"
if [[ -d "\$ED_DIR" ]]; then
    for ver_dir in "\$ED_DIR"/*/; do
        patched=0
        for jsfile in "\$ver_dir/background.js" "\$ver_dir/popup.js"; do
            [[ -f "\$jsfile" ]] || continue
            python3 -c "
with open('\$jsfile','r') as f: c=f.read()
o=c
c=c.replace('\"env\":\"prod\"', '\"env\":\"dev\"')
if c!=o:
    with open('\$jsfile','w') as f: f.write(c)
    print('Eduphoria %s: patched' % '\$jsfile'.split('/')[-1])
else:
    print('Eduphoria %s: ok' % '\$jsfile'.split('/')[-1])
" 2>/dev/null || true
            patched=1
        done
        [[ \$patched -eq 1 ]] && python3 "\$REHASH" "\$ver_dir" 2>/dev/null
    done
fi
PATCHEOF
    chmod +x /opt/chrome-direct/patch-extensions.sh
    log_info "Extension patch script created at /opt/chrome-direct/patch-extensions.sh"

    # Create Eduphoria Preferences injector (auto-registers unpacked extension)
    cat > /opt/chrome-direct/inject-unpacked.py << INJEOF
#!/usr/bin/env python3
"""Inject unpacked Eduphoria into Chrome Preferences before launch."""
import json, os, sys

PREFS_FILE = "$user_home/.config/chrome-direct/Default/Preferences"
EXT_ID = "egbobbmkefefhmoddnnpfgomegoccgoe"
EXT_PATH = "/opt/chrome-direct/eduphoria"

ENTRY = {
    "account_extension_type": 0,
    "active_permissions": {
        "api": ["activeTab","browsingData","clipboardRead","clipboardWrite",
                "contentSettings","cookies","history","management","storage",
                "system.display","tabs","webNavigation","webRequest",
                "scripting","declarativeNetRequestWithHostAccess"],
        "explicit_host": ["<all_urls>","http://*/*","https://*/*"],
        "manifest_permissions": [], "scriptable_host": []
    },
    "commands": {"_execute_action": {"was_assigned": True}},
    "content_settings": [], "creation_flags": 38, "disable_reasons": [],
    "filtered_service_worker_events": {
        "webNavigation.onBeforeNavigate": [{}],
        "webNavigation.onCompleted": [{}]
    },
    "first_install_time": "13414981309116939",
    "from_webstore": False,
    "granted_permissions": {
        "api": ["activeTab","browsingData","clipboardRead","clipboardWrite",
                "contentSettings","cookies","history","management","storage",
                "system.display","tabs","webNavigation","webRequest",
                "scripting","declarativeNetRequestWithHostAccess"],
        "explicit_host": ["<all_urls>","http://*/*","https://*/*"],
        "manifest_permissions": [], "scriptable_host": []
    },
    "incognito_content_settings": [], "incognito_preferences": {},
    "last_update_time": "13414981309116939",
    "location": 4, "newAllowFileAccess": True,
    "path": EXT_PATH, "preferences": {}, "regular_only_preferences": {},
    "service_worker_registration_info": {"version": "0.4.60"},
    "serviceworkerevents": [
        "tabs.onRemoved","tabs.onUpdated",
        "webRequest.onBeforeRequest/s1","webRequest.onHeadersReceived/s2"
    ],
    "was_installed_by_default": False, "was_installed_by_oem": False,
    "web_request": {"filtered_lazy_listeners": [
        {"extra_info_spec": 0, "filter": {"urls": ["<all_urls>"]},
         "sub_event_name": "webRequest.onBeforeRequest/s1"},
        {"extra_info_spec": 2, "filter": {"urls": ["<all_urls>"]},
         "sub_event_name": "webRequest.onHeadersReceived/s2"}
    ]},
    "withholding_permissions": False
}

if not os.path.isdir(EXT_PATH) or not os.path.isfile(PREFS_FILE):
    sys.exit(0)

with open(PREFS_FILE, 'r') as f:
    prefs = json.load(f)

settings = prefs.setdefault("extensions", {}).setdefault("settings", {})
if EXT_ID in settings and settings[EXT_ID].get("path") == EXT_PATH and settings[EXT_ID].get("location") == 4:
    print("Eduphoria: already registered")
    sys.exit(0)

settings[EXT_ID] = ENTRY
with open(PREFS_FILE, 'w') as f:
    json.dump(prefs, f, separators=(',', ':'))
print("Eduphoria: injected into Preferences")
INJEOF
    chmod +x /opt/chrome-direct/inject-unpacked.py
    log_info "Eduphoria Preferences injector created"
}

phase2_install_moonlight() {
    log_step "Installing Moonlight..."

    if is_done "install_moonlight"; then
        log_info "Already done, skipping"
        return
    fi

    local user_home="/home/$NEW_USERNAME"
    local appimage_dir="$user_home/AppImages"

    mkdir -p "$appimage_dir"
    curl -L -o "$appimage_dir/Moonlight.AppImage" \
        "https://github.com/moonlight-stream/moonlight-qt/releases/download/v6.1.0/Moonlight-6.1.0-x86_64.AppImage"
    chmod +x "$appimage_dir/Moonlight.AppImage"
    chown -R "$NEW_USERNAME:$NEW_USERNAME" "$appimage_dir"

    cat > /usr/share/applications/moonlight.desktop << EOF
[Desktop Entry]
Name=Moonlight
Exec=$appimage_dir/Moonlight.AppImage
Icon=moonlight
Type=Application
Categories=Game;
EOF
    log_info "Moonlight installed"
    mark_done "install_moonlight"
}

phase2_install_steam() {
    log_step "Installing Steam..."

    if is_done "install_steam"; then
        log_info "Already done, skipping"
        return
    fi

    # Steam requires 32-bit libraries
    dpkg --add-architecture i386
    apt update

    # Install bubblewrap (required for Steam sandbox) and dependencies
    apt install -y bubblewrap libgl1-mesa-dri:i386 libgl1:i386 \
        libc6:i386 libstdc++6:i386 2>/dev/null || true

    # Set bubblewrap suid (required for Steam's sandbox on some systems)
    if [[ -f /usr/bin/bwrap ]]; then
        chmod u+s /usr/bin/bwrap
        log_info "bubblewrap suid set"
    fi

    # Download and install Steam .deb
    local steam_deb="/tmp/steam.deb"
    curl -fsSL -o "$steam_deb" "https://cdn.akamai.steamstatic.com/client/installer/steam.deb"
    dpkg -i "$steam_deb" 2>/dev/null || true
    apt install -f -y
    rm -f "$steam_deb"

    log_info "Steam installed"
    mark_done "install_steam"
}

phase2_install_waydroid() {
    log_step "Installing Waydroid (Android container)..."

    if is_done "install_waydroid"; then
        log_info "Already done, skipping"
        return
    fi

    local user_home="/home/$NEW_USERNAME"

    # --- 1. Load bridge kernel module (required for waydroid networking) ---
    modprobe bridge 2>/dev/null || true
    if ! grep -q '^bridge$' /etc/modules-load.d/waydroid.conf 2>/dev/null; then
        echo "bridge" > /etc/modules-load.d/waydroid.conf
        log_info "Bridge module set to auto-load on boot"
    fi

    # --- 2. Add Waydroid apt repo ---
    local codename
    codename=$(. /etc/os-release && echo "$VERSION_CODENAME")
    # Fallback to bookworm if codename not detected or not in waydroid repo
    case "$codename" in
        bookworm|trixie|bullseye|sid|focal|jammy|noble) ;;
        *) codename="bookworm" ;;
    esac

    if [[ ! -f /usr/share/keyrings/waydroid.gpg ]]; then
        curl -fsSL "https://repo.waydro.id/waydroid.gpg" -o /usr/share/keyrings/waydroid.gpg
    fi
    echo "deb [signed-by=/usr/share/keyrings/waydroid.gpg] https://repo.waydro.id/ $codename main" \
        > /etc/apt/sources.list.d/waydroid.list
    apt update
    log_info "Waydroid repo added for: $codename"

    # --- 3. Install Waydroid and dependencies ---
    apt install -y waydroid python3 lxc
    log_info "Waydroid package installed"

    # --- 4-7. Shimboot kernel workarounds ---
    # This setup script targets shimboot systems with kernel 5.4.x which has:
    # - ChromeOS LSM blocking mount() through symlinks (breaks LXC)
    # - Missing iptables CHECKSUM target
    # - userfaultfd flags not supported (crashes Android 13 ART)
    # Always apply these workarounds — this is a shimboot setup script.
    local is_shimboot_kernel=true
    log_info "Applying shimboot kernel workarounds"

    if [[ "$is_shimboot_kernel" == "true" ]]; then
        # --- 4. ChromeOS LSM sb_mount bypass (LD_PRELOAD mount fix) ---
        # ChromeOS kernel's LSM blocks mount() when the path traverses symlinks.
        # LXC's safe_mount() uses /proc/self/fd/<N> paths which are symlinks,
        # triggering "Mount path with symlinks prohibited". This LD_PRELOAD library
        # intercepts mount() and resolves /proc/self/fd/ paths via readlink() first.
        log_info "Compiling ChromeOS LSM mount fix..."

        # Ensure build tools are available (need gcc + libc headers)
        apt install -y build-essential || apt install -y gcc libc6-dev || true

        local mount_fix_src=$(mktemp /tmp/mount_fix_XXXXXX.c)
        cat > "$mount_fix_src" << 'CEOF'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>
#include <errno.h>
#include <limits.h>

static int resolve_proc_fd(const char *proc_fd_path, char *out, size_t outlen) {
    ssize_t len = readlink(proc_fd_path, out, outlen - 1);
    if (len < 0) return -1;
    out[len] = '\0';
    return 0;
}

int mount(const char *source, const char *target,
          const char *filesystemtype, unsigned long mountflags,
          const void *data)
{
    static int (*real_mount)(const char *, const char *, const char *,
                             unsigned long, const void *) = NULL;
    if (!real_mount)
        real_mount = dlsym(RTLD_NEXT, "mount");

    char resolved_source[PATH_MAX], resolved_target[PATH_MAX];
    const char *use_source = source, *use_target = target;

    if (source && strstr(source, "/proc/") && strstr(source, "/fd/"))
        if (resolve_proc_fd(source, resolved_source, sizeof(resolved_source)) == 0)
            use_source = resolved_source;

    if (target && strstr(target, "/proc/") && strstr(target, "/fd/"))
        if (resolve_proc_fd(target, resolved_target, sizeof(resolved_target)) == 0)
            use_target = resolved_target;

    return real_mount(use_source, use_target, filesystemtype, mountflags, data);
}
CEOF
        if gcc -shared -fPIC -o /usr/lib/waydroid-mount-fix.so "$mount_fix_src" -ldl; then
            log_info "waydroid-mount-fix.so compiled and installed"
        else
            log_error "FAILED to compile waydroid-mount-fix.so (missing gcc or libc6-dev?)"
            log_error "Waydroid will NOT work without this. Install build-essential and re-run."
        fi
        rm -f "$mount_fix_src"

        # --- 5. Wrap lxc-start to inject LD_PRELOAD ---
        if [[ -f /usr/bin/lxc-start && ! -f /usr/bin/lxc-start.real ]]; then
            mv /usr/bin/lxc-start /usr/bin/lxc-start.real
        fi
        cat > /usr/bin/lxc-start << 'WRAPEOF'
#!/bin/bash
# Wrapper to fix ChromeOS LSM sb_mount symlink restriction for LXC containers
# Resolves /proc/self/fd/N to actual paths to avoid symlink traversal
export LD_PRELOAD=/usr/lib/waydroid-mount-fix.so${LD_PRELOAD:+:$LD_PRELOAD}
exec /usr/bin/lxc-start.real "$@"
WRAPEOF
        chmod +x /usr/bin/lxc-start
        log_info "lxc-start wrapper installed"

        # --- 6. Patch waydroid-net.sh: CHECKSUM iptables target (missing in ChromeOS kernel) ---
        # Kernel 5.4 lacks xt_CHECKSUM module — iptables fails with "No chain/target/match"
        local net_script="/usr/lib/waydroid/data/scripts/waydroid-net.sh"
        if [[ -f "$net_script" ]]; then
            # Find lines with -j CHECKSUM, skip already-patched, append error suppression
            sed -i '/-j CHECKSUM/{/2>\/dev\/null/!s/$/ 2>\/dev\/null || true/;}' "$net_script"
            log_info "waydroid-net.sh CHECKSUM rules patched"
        fi

        # --- 7. Patch seccomp: userfaultfd errno 38 ---
        # Android 13 ART tries userfaultfd() with flags not supported by kernel 5.4.
        # Returns EINVAL instead of ENOSYS/EACCES, causing a fatal CHECK failure.
        local seccomp_file="/usr/lib/waydroid/data/configs/waydroid.seccomp"
        if [[ -f "$seccomp_file" ]] && ! grep -q "^userfaultfd errno 38$" "$seccomp_file"; then
            echo "userfaultfd errno 38" >> "$seccomp_file"
            log_info "userfaultfd errno 38 added to seccomp profile"
        fi
    fi  # is_shimboot_kernel

    # --- 8. Initialize Waydroid with GAPPS ---
    log_info "Initializing Waydroid with GAPPS image (this may take a while)..."
    local init_ok=false
    for attempt in 1 2 3; do
        if waydroid init -s GAPPS -f; then
            # Verify init actually produced a valid config
            if [[ -f /var/lib/waydroid/waydroid.cfg ]] && grep -q "images_path" /var/lib/waydroid/waydroid.cfg 2>/dev/null; then
                init_ok=true
                break
            else
                log_warn "waydroid init completed but config looks incomplete (attempt $attempt/3)"
            fi
        else
            log_warn "waydroid init failed (attempt $attempt/3)"
        fi
        sleep 3
    done
    if [[ "$init_ok" != "true" ]]; then
        log_error "Waydroid init failed after 3 attempts. Run manually: waydroid init -s GAPPS -f"
    fi

    # --- 8b. Re-patch active seccomp after init (belt-and-suspenders) ---
    # waydroid init creates a copy at /var/lib/waydroid/lxc/waydroid/waydroid.seccomp
    # which may not have our template patch if init re-generates it
    if [[ "$is_shimboot_kernel" == "true" ]]; then
        local active_seccomp="/var/lib/waydroid/lxc/waydroid/waydroid.seccomp"
        if [[ -f "$active_seccomp" ]] && ! grep -q "^userfaultfd errno 38$" "$active_seccomp"; then
            echo "userfaultfd errno 38" >> "$active_seccomp"
            log_info "userfaultfd errno 38 added to active seccomp profile"
        fi
    fi

    # --- 9. Add persistent properties ---
    # Suppress ANR "not responding" dialogs (games trigger these frequently)
    # Disable strict mode (reduces crashes/dialogs in games)
    local base_prop="/var/lib/waydroid/waydroid_base.prop"
    local waydroid_cfg="/var/lib/waydroid/waydroid.cfg"

    # Build property list (uffd_gc only needed on ChromeOS/old kernels)
    local props=(
        "persist.sys.anr_timeout=60000"
        "persist.sys.anr_show_dialog=0"
        "persist.sys.strictmode.disable=true"
    )
    if [[ "$is_shimboot_kernel" == "true" ]]; then
        props+=("persist.device_config.runtime_native_boot.enable_uffd_gc=false")
    fi

    # Add to base props (direct runtime properties)
    for prop in "${props[@]}"; do
        prop_key="${prop%%=*}"
        if ! grep -q "^${prop_key}=" "$base_prop" 2>/dev/null; then
            echo "$prop" >> "$base_prop"
        fi
    done
    log_info "Waydroid properties configured (ANR suppressed)"

    # Add uffd_gc to waydroid.cfg [properties] section (survives waydroid init)
    if [[ "$is_shimboot_kernel" == "true" ]]; then
        if ! grep -q "enable_uffd_gc" "$waydroid_cfg" 2>/dev/null; then
            if grep -q '^\[properties\]' "$waydroid_cfg"; then
                sed -i '/^\[properties\]/a persist.device_config.runtime_native_boot.enable_uffd_gc = false' "$waydroid_cfg"
            else
                printf '\n[properties]\npersist.device_config.runtime_native_boot.enable_uffd_gc = false\n' >> "$waydroid_cfg"
            fi
        fi
    fi

    # --- 10. Tailscale routing fix ---
    # Tailscale's policy routing (table 52) captures waydroid's bridge subnet
    # and tries to route it through tailscale0, breaking return packets to the
    # container. Add a rule to keep packets TO waydroid in the main table.
    # Outbound waydroid traffic still goes through Tailscale VPN (table 52).
    if command -v tailscale &>/dev/null; then
        ip rule del to 192.168.240.0/24 lookup main priority 5200 2>/dev/null || true
        ip rule add to 192.168.240.0/24 lookup main priority 5200
        log_info "Tailscale routing fix applied (waydroid bridge reachable)"
    fi

    # --- 11. Enable and start Waydroid ---
    systemctl enable waydroid-container
    systemctl start waydroid-container 2>/dev/null || log_warn "Container start may need reboot"

    # --- 12. Get Android ID for Play Store registration ---
    sleep 5
    local android_id=""
    android_id=$(sudo waydroid shell -- sqlite3 /data/data/com.google.android.gsf/databases/gservices.db \
        "select * from main where name = 'android_id';" 2>/dev/null | cut -d'|' -f2) || true

    log_info "Waydroid installed and running"
    if [[ -n "$android_id" ]]; then
        log_info "Android ID: $android_id"
        log_info "Register at: https://www.google.com/android/uncertified"
    else
        log_warn "Android ID not yet available (container may still be booting)"
        log_warn "Run later: sudo waydroid shell -- sqlite3 /data/data/com.google.android.gsf/databases/gservices.db \"select * from main where name = 'android_id';\""
    fi

    mark_done "install_waydroid"
}

phase2_setup_mac_changer() {
    log_step "Setting up MAC changer..."

    if is_done "setup_mac_changer" && [[ -x "/usr/local/bin/mac-change" ]]; then
        log_info "Already done, skipping"
        return
    fi

    DEBIAN_FRONTEND=noninteractive apt install -y macchanger 2>/dev/null || true

    cat > /usr/local/bin/mac-change << 'EOF'
#!/bin/bash
source /opt/setup/setup.conf
IFACE="${NETWORK_INTERFACE:-wlan0}"
echo "Randomizing MAC on $IFACE..."
sudo ip link set "$IFACE" down
sudo macchanger -r "$IFACE" 2>/dev/null || {
    MAC=$(printf '02:%02x:%02x:%02x:%02x:%02x' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))
    sudo ip link set "$IFACE" address "$MAC"
}
sudo ip link set "$IFACE" up
EOF

    cat > /usr/local/bin/mac-restore << 'EOF'
#!/bin/bash
source /opt/setup/setup.conf
IFACE="${NETWORK_INTERFACE:-wlan0}"
sudo ip link set "$IFACE" down
sudo macchanger -p "$IFACE" 2>/dev/null || echo "Reboot to restore"
sudo ip link set "$IFACE" up
EOF

    chmod +x /usr/local/bin/mac-change /usr/local/bin/mac-restore

    cat > /etc/systemd/system/mac-changer.service << 'EOF'
[Unit]
Description=MAC Randomizer
Before=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/mac-change
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    [[ "$MAC_CHANGER_ENABLED" == "true" ]] && systemctl enable mac-changer.service

    log_info "MAC changer configured"
    mark_done "setup_mac_changer"
}

phase2_disable_kwallet() {
    log_step "Disabling KDE Wallet..."

    if is_done "disable_kwallet"; then
        log_info "Already done, skipping"
        return
    fi

    local user_home="/home/$NEW_USERNAME"
    rm -f "$user_home/.local/share/kwalletd/kdewallet.kwl" "$user_home/.local/share/kwalletd/kdewallet.salt" 2>/dev/null || true

    mkdir -p "$user_home/.config"
    cat > "$user_home/.config/kwalletrc" << 'EOF'
[Wallet]
First Use=false
Enabled=false
EOF
    chown "$NEW_USERNAME:$NEW_USERNAME" "$user_home/.config/kwalletrc"

    # Kill running kwalletd5 so it picks up the new config on next start
    # (kwalletd5 caches config in memory; just writing kwalletrc isn't enough)
    pkill -u "$NEW_USERNAME" kwalletd5 2>/dev/null || true

    log_info "KDE Wallet disabled"
    mark_done "disable_kwallet"
}

phase2_system_update() {
    log_step "System update..."

    if is_done "system_update"; then
        log_info "Already done, skipping"
        return
    fi

    apt update && apt upgrade -y
    apt autoremove -y
    log_info "System updated"
    mark_done "system_update"
}

phase2_setup_kiosk_lock() {
    log_step "Setting up kiosk lock (Ctrl+Shift+L)..."

    local user_home="/home/$NEW_USERNAME"

    # 1. Main toggle script
    cat > /usr/local/bin/kiosk-lock << 'LOCKEOF'
#!/bin/bash
# Kiosk Lock - Toggle fullscreen lock mode
# Bound to Ctrl+Shift+L via KDE custom shortcuts
#
# Lock: fullscreens active window, enforces focus, disables shortcuts,
#        hides panels, blocks VT switching
# Unlock: reverses everything

# Prevent KDE from creating a taskbar entry for this script
unset DESKTOP_STARTUP_ID

LOCK_STATE="/tmp/kiosk-lock.state"
BACKUP="/tmp/kiosk-lock-shortcuts.bak"
SCRIPT_DIR="/usr/local/lib/kiosk-lock"
KWIN_SCRIPT_NAME="kiosk_lock_enforce"

run_kwin_script() {
    local script="$1"
    local name="$2"
    local persist="${3:-false}"

    qdbus org.kde.KWin /Scripting org.kde.kwin.Scripting.loadScript "$script" "$name" >/dev/null 2>&1
    qdbus org.kde.KWin /Scripting org.kde.kwin.Scripting.start >/dev/null 2>&1

    if [ "$persist" != "true" ]; then
        sleep 0.3
        qdbus org.kde.KWin /Scripting org.kde.kwin.Scripting.unloadScript "$name" >/dev/null 2>&1
    fi
}

disable_shortcuts() {
    local src="$HOME/.config/kglobalshortcutsrc"
    cp "$src" "$BACKUP"

    # Set all current shortcut bindings to "none" except [khotkeys] section
    awk '
    BEGIN { in_khotkeys = 0 }
    /^\[khotkeys\]/ { in_khotkeys = 1; print; next }
    /^\[/ { in_khotkeys = 0 }
    in_khotkeys { print; next }
    /^[^_\[#][^=]*=.*,/ {
        eq = index($0, "=")
        name = substr($0, 1, eq)
        val = substr($0, eq + 1)
        comma = index(val, ",")
        if (comma > 0) {
            rest = substr(val, comma)
            print name "none" rest
            next
        }
    }
    { print }
    ' "$src" > "${src}.tmp" && mv "${src}.tmp" "$src"

    qdbus org.kde.KWin /KWin org.kde.KWin.reconfigure >/dev/null 2>&1
}

restore_shortcuts() {
    if [ -f "$BACKUP" ]; then
        cp "$BACKUP" "$HOME/.config/kglobalshortcutsrc"
        rm -f "$BACKUP"
        qdbus org.kde.KWin /KWin org.kde.KWin.reconfigure >/dev/null 2>&1
    fi
}

lock() {
    # 1. Load persistent KWin script: fullscreens active window + enforces focus
    run_kwin_script "$SCRIPT_DIR/focus-enforce.js" "$KWIN_SCRIPT_NAME" true

    # 2. Hide panels (autohide so they don't show over fullscreen)
    qdbus org.kde.plasmashell /PlasmaShell org.kde.PlasmaShell.evaluateScript \
        'panels().forEach(function(p) { p.hiding = "windowscover"; })' >/dev/null 2>&1

    # 3. Disable all keyboard shortcuts except our unlock shortcut
    disable_shortcuts &

    # 4. Block VT switching
    sudo /usr/local/bin/kiosk-vt-ctl lock >/dev/null 2>&1 &

    # 5. Mark locked
    echo "locked" > "$LOCK_STATE"
}

unlock() {
    # 1. Restore shortcuts first (so reconfigure happens)
    restore_shortcuts

    # 2. Unload focus enforcement script first (stops re-forcing fullscreen)
    qdbus org.kde.KWin /Scripting org.kde.kwin.Scripting.unloadScript "$KWIN_SCRIPT_NAME" >/dev/null 2>&1

    # 3. Unfullscreen active window + restore all windows in Alt+Tab
    local tmpscript
    tmpscript=$(mktemp /tmp/kiosk_unfs_XXXXX.js)
    cat > "$tmpscript" << 'UNFSEOF'
(function() {
    if (workspace.activeClient) workspace.activeClient.fullScreen = false;
    var clients = workspace.clientList();
    for (var i = 0; i < clients.length; i++) {
        clients[i].skipSwitcher = false;
        clients[i].skipTaskbar = false;
    }
})();
UNFSEOF
    run_kwin_script "$tmpscript" "kiosk_unfs"
    rm -f "$tmpscript"

    # 4. Show panels
    qdbus org.kde.plasmashell /PlasmaShell org.kde.PlasmaShell.evaluateScript \
        'panels().forEach(function(p) { p.hiding = "none"; })' >/dev/null 2>&1

    # 5. Unblock VT switching
    sudo /usr/local/bin/kiosk-vt-ctl unlock >/dev/null 2>&1

    # 6. Remove lock state
    rm -f "$LOCK_STATE"
}

# Toggle
if [ -f "$LOCK_STATE" ]; then
    unlock
else
    lock
fi
LOCKEOF
    chmod +x /usr/local/bin/kiosk-lock

    # 2. KWin focus enforcement script
    mkdir -p /usr/local/lib/kiosk-lock
    cat > /usr/local/lib/kiosk-lock/focus-enforce.js << 'JSEOF'
(function() {
    var target = workspace.activeClient;
    if (!target) return;

    target.fullScreen = true;

    // Hide ALL other windows from Alt+Tab so they can't be seen
    var clients = workspace.clientList();
    for (var i = 0; i < clients.length; i++) {
        if (clients[i] !== target) {
            clients[i].skipSwitcher = true;
            clients[i].skipTaskbar = true;
        }
    }

    // Re-force fullscreen if user clicks Chrome's "exit fullscreen" X
    target.fullScreenChanged.connect(function() {
        if (target && !target.fullScreen) {
            target.fullScreen = true;
        }
    });

    // Enforce focus - immediately switch back if anything else activates
    function onActivated(client) {
        if (target && client !== target) {
            workspace.activeClient = target;
        }
    }

    // Hide any newly opened windows from switcher too
    function onClientAdded(client) {
        if (client !== target) {
            client.skipSwitcher = true;
            client.skipTaskbar = true;
        }
    }

    function onRemoved(client) {
        if (client === target) {
            target = null;
            workspace.clientActivated.disconnect(onActivated);
            workspace.clientRemoved.disconnect(onRemoved);
            workspace.clientAdded.disconnect(onClientAdded);
        }
    }

    workspace.clientActivated.connect(onActivated);
    workspace.clientRemoved.connect(onRemoved);
    workspace.clientAdded.connect(onClientAdded);
})();
JSEOF

    # 3. VT switching control helper (runs as root via sudoers)
    cat > /usr/local/bin/kiosk-vt-ctl << 'VTEOF'
#!/bin/bash
case "$1" in
    lock)
        for f in /sys/class/vtconsole/vtcon*/bind; do
            [ -f "$f" ] && echo 0 > "$f"
        done
        ;;
    unlock)
        for f in /sys/class/vtconsole/vtcon*/bind; do
            [ -f "$f" ] && echo 1 > "$f"
        done
        ;;
esac
VTEOF
    chmod +x /usr/local/bin/kiosk-vt-ctl

    # 4. Sudoers entry for passwordless VT control
    echo "$NEW_USERNAME ALL=(root) NOPASSWD: /usr/local/bin/kiosk-vt-ctl" > /etc/sudoers.d/kiosk-lock
    chmod 440 /etc/sudoers.d/kiosk-lock

    # 5. Register Ctrl+Shift+L shortcut in khotkeys (kded module)
    local khotkeysrc="$user_home/.config/khotkeysrc"
    local uuid="{f47ac10b-58cc-4372-a567-0e02b2c3d479}"

    # Only add if not already present
    if ! grep -q "Kiosk Lock" "$khotkeysrc" 2>/dev/null; then
        # Increment DataCount in [Data] section
        local current_count
        current_count=$(sed -n '/^\[Data\]$/,/^\[/{s/^DataCount=//p}' "$khotkeysrc" 2>/dev/null)
        if [[ -n "$current_count" ]]; then
            local new_count=$((current_count + 1))
            sed -i "/^\[Data\]$/,/^\[/{s/^DataCount=$current_count/DataCount=$new_count/}" "$khotkeysrc"

            # Append new shortcut entry before [DirSelect Dialog] or at end of Data sections
            cat >> "$khotkeysrc" << HOTEOF

[Data_${new_count}]
Comment=Toggle Kiosk Lock (fullscreen + block escape)
Enabled=true
Name=Kiosk Lock
Type=SIMPLE_ACTION_DATA

[Data_${new_count}Actions]
ActionsCount=1

[Data_${new_count}Actions0]
CommandURL=/usr/local/bin/kiosk-lock
Type=COMMAND_URL

[Data_${new_count}Conditions]
Comment=
ConditionsCount=0

[Data_${new_count}Triggers]
Comment=Simple_action
TriggersCount=1

[Data_${new_count}Triggers0]
Key=Ctrl+Shift+L
Type=SHORTCUT
Uuid=$uuid
HOTEOF
            chown "$NEW_USERNAME:$NEW_USERNAME" "$khotkeysrc"
            log_info "Registered Ctrl+Shift+L in khotkeysrc"
        else
            # khotkeysrc doesn't exist or has no DataCount — create full config
            cat > "$khotkeysrc" << HOTEOF2
[\$Version]
update_info=konsole_globalaccel.upd:konsole_globalaccel

[Data]
DataCount=1

[Data_1]
Comment=Toggle Kiosk Lock (fullscreen + block escape)
Enabled=true
Name=Kiosk Lock
Type=SIMPLE_ACTION_DATA

[Data_1Actions]
ActionsCount=1

[Data_1Actions0]
CommandURL=/usr/local/bin/kiosk-lock
Type=COMMAND_URL

[Data_1Conditions]
Comment=
ConditionsCount=0

[Data_1Triggers]
Comment=Simple_action
TriggersCount=1

[Data_1Triggers0]
Key=Ctrl+Shift+L
Type=SHORTCUT
Uuid=$uuid

[Gestures]
Disabled=true
MouseButton=2
Timeout=300

[GesturesExclude]
Comment=
WindowsCount=0

[Main]
AlreadyImported=defaults
Disabled=false
Version=2

[Voice]
Shortcut=
HOTEOF2
            chown "$NEW_USERNAME:$NEW_USERNAME" "$khotkeysrc"
            log_info "Created khotkeysrc with Kiosk Lock shortcut"
        fi
    else
        log_info "Kiosk Lock shortcut already registered"
    fi

    # 6. Register shortcut in kglobalshortcutsrc (required for KDE to activate it)
    local kglobalrc="$user_home/.config/kglobalshortcutsrc"
    if ! grep -q "$uuid" "$kglobalrc" 2>/dev/null; then
        # Ensure [khotkeys] section exists with the binding
        if grep -q '^\[khotkeys\]' "$kglobalrc" 2>/dev/null; then
            # Add our shortcut entry after the [khotkeys] section header
            sed -i "/^\[khotkeys\]/a ${uuid}=Ctrl+Shift+L,none,Kiosk Lock" "$kglobalrc"
        else
            # Create the section
            cat >> "$kglobalrc" << KGEOF

[khotkeys]
_k_friendly_name=Custom Shortcuts Service
${uuid}=Ctrl+Shift+L,none,Kiosk Lock
KGEOF
        fi
        chown "$NEW_USERNAME:$NEW_USERNAME" "$kglobalrc"
        log_info "Registered Ctrl+Shift+L in kglobalshortcutsrc"
    fi

    # 7. Reload khotkeys to pick up new config
    # Need user's DBUS_SESSION_BUS_ADDRESS since we're running as root
    local user_dbus=""
    local kded_pid
    kded_pid=$(pgrep -u "$NEW_USERNAME" kded5 2>/dev/null | head -1)
    if [[ -n "$kded_pid" ]]; then
        user_dbus=$(grep -z DBUS_SESSION_BUS_ADDRESS "/proc/$kded_pid/environ" 2>/dev/null | tr '\0' '\n' | sed 's/^DBUS_SESSION_BUS_ADDRESS=//')
    fi
    if [[ -n "$user_dbus" ]]; then
        sudo -u "$NEW_USERNAME" DBUS_SESSION_BUS_ADDRESS="$user_dbus" \
            qdbus org.kde.kded5 /kded org.kde.kded5.loadModule khotkeys 2>/dev/null || true
        sudo -u "$NEW_USERNAME" DBUS_SESSION_BUS_ADDRESS="$user_dbus" \
            qdbus org.kde.KWin /KWin org.kde.KWin.reconfigure 2>/dev/null || true
        log_info "khotkeys reloaded via D-Bus"
    else
        log_warn "Could not find user's D-Bus session — shortcut will work after next login/reboot"
    fi

    log_info "Kiosk lock installed (Ctrl+Shift+L to toggle)"
}

phase2_fix_permissions() {
    log_step "Fixing permissions..."

    local scripts=(
        "/usr/local/bin/vpn-on"
        "/usr/local/bin/vpn-off"
        "/usr/local/bin/mac-change"
        "/usr/local/bin/mac-restore"
        "/usr/local/bin/chrome-netns-setup.sh"
        "/usr/local/bin/chrome-direct"
        "/usr/local/bin/install-ssl-cert"
        "/usr/local/bin/setup"
        "/opt/chrome-direct/patch-extensions.sh"
        "/opt/chrome-direct/keep-active.sh"
        "/opt/chrome-direct/inject-unpacked.py"
        "/usr/bin/lxc-start"
        "/usr/local/bin/kiosk-lock"
        "/usr/local/bin/kiosk-vt-ctl"
        "$INSTALL_DIR/setup.sh"
    )

    for s in "${scripts[@]}"; do
        [[ -f "$s" ]] && chmod +x "$s"
    done

    systemctl daemon-reload
    log_info "Permissions fixed"
}

run_phase2() {
    echo ""
    echo "========================================"
    echo "  PHASE 2: Setup System"
    echo "========================================"
    echo ""

    phase2_check_user
    phase2_delete_old_user
    phase2_remove_bloat
    phase2_install_deps
    phase2_install_brave
    phase2_install_vscode
    phase2_install_chrome
    phase2_install_tailscale
    phase2_setup_vpn
    phase2_setup_chrome_netns
    phase2_setup_chrome_extensions
    phase2_setup_chrome_certs
    phase2_install_moonlight
    phase2_install_steam
    phase2_install_waydroid
    phase2_setup_mac_changer
    phase2_setup_kiosk_lock
    phase2_disable_kwallet
    phase2_system_update
    phase2_fix_permissions

    mark_done "phase2"

    echo ""
    echo "========================================"
    log_info "Setup complete!"
    echo "========================================"
    echo ""
    echo "Commands:"
    echo "  vpn-on / vpn-off      - Toggle VPN"
    echo "  mac-change / restore  - MAC tools"
    echo "  chrome-direct         - Chrome (no VPN, ChromeOS spoofed)"
    echo "  install-ssl-cert      - Add SSL certs"
    echo "  steam                 - Steam client"
    echo "  waydroid show-full-display - Launch Waydroid UI"
    echo "  Ctrl+Shift+L          - Toggle kiosk lock"
    echo ""
    echo "Services:"
    echo "  systemctl start/stop tailscale-vpn"
    echo "  systemctl start/stop mac-changer"
    echo "  systemctl start/stop chrome-netns"
    echo "  systemctl start/stop waydroid-container"
    echo ""
    echo "Paths:"
    echo "  Config:      $CONF_FILE"
    echo "  Extensions:  /opt/chrome-extensions/"
    echo "  Patcher:     /opt/chrome-direct/patch-extensions.sh"
    echo "  Policy:      /etc/opt/chrome/policies/managed/"
    echo ""
}

# ============================================
# Main
# ============================================
main() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Run with sudo: sudo $0"
        exit 1
    fi

    case "${1:-}" in
        --status) show_status; exit 0 ;;
        --reset=1|--reset=phase1)
            # Full reset: clear ALL progress, start from scratch
            rm -f "$STATUS_FILE"
            touch "$STATUS_FILE"
            log_info "Full reset. All progress cleared. Run 'sudo setup' to start from phase 1."
            exit 0
            ;;
        --reset=2|--reset=phase2)
            # Reset phase 2 only: keep phase 1 done, re-run phase 2
            if [[ ! -f "$STATUS_FILE" ]]; then
                log_error "No status file found. Nothing to reset."
                exit 1
            fi
            # Keep only phase1 entries, wipe everything else
            grep -E '^(phase1|create_user|set_hostname)=done$' "$STATUS_FILE" > "${STATUS_FILE}.tmp" 2>/dev/null || true
            mv "${STATUS_FILE}.tmp" "$STATUS_FILE"
            log_info "Phase 2 progress cleared. Run 'sudo setup' to re-run phase 2."
            exit 0
            ;;
        --help)
            echo "Usage: sudo setup [--status|--reset=1|--reset=2|--help]"
            echo ""
            echo "  (no args)  Run setup (auto-detects phase)"
            echo "  --status   Show completed steps"
            echo "  --reset=1  Full reset (back to beginning of phase 1)"
            echo "  --reset=2  Reset phase 2 only (re-run from beginning of phase 2)"
            echo "  --help     Show this help"
            exit 0
            ;;
    esac

    load_config
    install_system_wide

    echo ""
    echo "========================================"
    echo "  Shimboot Setup"
    echo "========================================"
    echo "  Old User:  $OLD_USERNAME"
    echo "  New User:  $NEW_USERNAME"
    echo "  Hostname:  $HOSTNAME"
    echo "========================================"
    echo ""

    local phase=$(get_phase)
    log_info "Phase: $phase"

    if [[ "$phase" == "1" ]]; then
        run_phase1
    else
        run_phase2
    fi
}

main "$@"
