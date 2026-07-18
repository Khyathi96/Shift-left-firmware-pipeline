#!/bin/bash
# Custom CVE check for OpenWrt opkg package databases.
# Why this exists: Trivy/Grype don't parse opkg's status format,
# so embedded-Linux packages are invisible to standard CVE scanners.
set -euo pipefail

STATUS_FILE="${1:?Usage: $0 <opkg status file> [output.json]}"
OUT="${2:-opkg_cve_results.json}"

# Mini vulnerability DB: package|fixed_in|CVE|severity|description
VULNDB='busybox|1.25.0|CVE-2016-2147|MEDIUM|Integer overflow in BusyBox DHCP client (udhcpc) allows DoS via crafted OPTION_6RD
busybox|1.25.0|CVE-2016-2148|HIGH|Heap-based buffer overflow in BusyBox DHCP client (udhcpc) allows remote code execution'

echo '{ "scanner": "opkg_cve_check", "findings": [' > "$OUT"
FIRST=1

# Walk the status file, remembering each Package/Version pair
while read -r key value; do
  [ "$key" = "Package:" ] && PKG="$value"
  if [ "$key" = "Version:" ]; then
    VER="${value%%-*}"   # strip opkg revision suffix: 1.19.4-1 -> 1.19.4
    # Look up this package in our vuln DB
    while IFS='|' read -r vpkg fixed cve sev desc; do
      [ "$vpkg" = "$PKG" ] || continue
      # Vulnerable if installed version sorts below the fixed version
      LOWEST=$(printf '%s\n%s\n' "$VER" "$fixed" | sort -V | head -n 1)
      if [ "$LOWEST" = "$VER" ] && [ "$VER" != "$fixed" ]; then
        [ $FIRST -eq 0 ] && echo ',' >> "$OUT"
        printf '{"package":"%s","installed":"%s","fixed_in":"%s","cve":"%s","severity":"%s","description":"%s"}' \
          "$PKG" "$VER" "$fixed" "$cve" "$sev" "$desc" >> "$OUT"
        FIRST=0
      fi
    done <<< "$VULNDB"
  fi
done < "$STATUS_FILE"

echo '] }' >> "$OUT"
echo "[+] opkg CVE check complete -> $OUT"