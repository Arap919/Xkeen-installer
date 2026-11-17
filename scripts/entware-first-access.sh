#!/opt/bin/sh
# Fresh Entware access gate. Never source credential files or enable shell tracing.
set -eu
PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin
export PATH
umask 077
base=/opt/etc/xkeen-bootstrap
credential=/opt/.xkeen-bootstrap-credential
ready=$base/ready
fail() { echo 'Первый доступ Entware заблокирован: проверьте завершение установки через KeeneticOS.' >&2; exit 1; }
regular() { [ -f "$1" ] && [ ! -L "$1" ]; }
state() {
    regular /opt/etc/passwd || return 1
    regular /opt/etc/dropbear/dropbear_rsa_host_key || return 1
    regular /opt/etc/dropbear/dropbear_ed25519_host_key || return 1
    [ -s /opt/etc/dropbear/dropbear_rsa_host_key ] && [ -s /opt/etc/dropbear/dropbear_ed25519_host_key ] || return 1
    # Require exactly one usable SHA-512-crypt root entry; no default/locked fallback.
    /opt/bin/awk -F: 'BEGIN {n=0;ok=0} $1=="root" {n++; if (NF==7 && $3=="0" && $4=="0" && $2 ~ /^\$6\$rounds=100000\$[.\/0-9A-Za-z]+\$[.\/0-9A-Za-z]+$/) ok++} END {exit !(n==1 && ok==1)}' /opt/etc/passwd || return 1
    /opt/bin/sha256sum /opt/etc/passwd /opt/etc/dropbear/dropbear_rsa_host_key /opt/etc/dropbear/dropbear_ed25519_host_key
}
revoke() {
    [ -d "$base" ] && [ ! -L "$base" ] || fail
    rm -f "$ready"
    init=/opt/etc/init.d/S51dropbear
    if [ -e "$init" ] || [ -L "$init" ]; then
        regular "$init" && "$init" stop >/dev/null 2>&1 || fail
    fi
}
case "${1:-}" in
revoke)
    revoke
    ;;
verify)
    [ -d "$base" ] && [ ! -L "$base" ] && regular "$ready" || fail
    [ "$(/opt/bin/wc -c < "$ready")" -lt 1024 ] || fail
    actual=$(state) || fail
    expected=$(/opt/bin/cat "$ready") || fail
    [ -n "$expected" ] && [ "$actual" = "$expected" ] || fail
    ;;
configure)
    revoke
    regular "$credential" && regular "$base/arch" || fail
    [ "$(/opt/bin/wc -c < "$credential")" -le 512 ] || fail
    arch=$(/opt/bin/cat "$base/arch")
    # Exact six-line, data-only payload; no shell evaluation or command substitution.
    /opt/bin/awk -v arch="$arch" '
      NR==1 && $0=="XKEEN-BOOTSTRAP-V1" {ok++;next}
      NR==2 && length($0)==32 && $0 !~ /[^a-f0-9]/ {ok++;next}
      NR==3 && $0 ~ /^[a-fA-F0-9-]+$/ && length($0)==36 {ok++;next}
      NR==4 && $0==arch {ok++;next}
      NR==5 && length($0)==64 && $0 !~ /[^a-f0-9]/ {ok++;next}
      NR==6 {n=split($0,p,"\\$");if(n==5 && p[1]=="" && p[2]=="6" && p[3]=="rounds=100000" && length(p[4])==16 && length(p[5])==86 && p[4] !~ /[^.\/0-9A-Za-z]/ && p[5] !~ /[^.\/0-9A-Za-z]/)ok++;next}
      END {exit !(NR==6 && ok==6)}' "$credential" || fail
    regular /opt/etc/passwd || fail
    tmp=$(/opt/bin/mktemp /opt/etc/.xkeen-passwd.XXXXXX) || fail
    trap 'rm -f "$tmp"' EXIT
    trap 'exit 1' HUP INT TERM
    /opt/bin/awk -F: 'NR==FNR {if(NR==6)h=$0;next} BEGIN {OFS=":";n=0}
      $1=="root" {if(NF!=7 || $3!="0" || $4!="0")exit 1; $2=h;n++} {print}
      END {if(n!=1)exit 1}' "$credential" /opt/etc/passwd > "$tmp" || fail
    chmod 600 "$tmp" || fail
    mv -f "$tmp" /opt/etc/passwd || fail
    # Invalidate all archive-provided host keys before generating either new key.
    rm -f /opt/etc/dropbear/dropbear_rsa_host_key /opt/etc/dropbear/dropbear_ed25519_host_key
    /opt/bin/dropbearkey -t rsa -f /opt/etc/dropbear/dropbear_rsa_host_key >/dev/null 2>&1 || fail
    /opt/bin/dropbearkey -t ed25519 -f /opt/etc/dropbear/dropbear_ed25519_host_key >/dev/null 2>&1 || fail
    tmp=$(/opt/bin/mktemp "$base/.ready.XXXXXX") || fail
    state > "$tmp" || fail
    chmod 600 "$tmp" || fail
    # Remove the transferable credential before publishing positive readiness.
    rm -f "$credential" || fail
    mv -f "$tmp" "$ready" || fail
    trap - EXIT HUP INT TERM
    ;;
*) fail ;;
esac
