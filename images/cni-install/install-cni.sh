#!/bin/sh

set -e

# Directory checks
CNI_BIN_DIR="/host/opt/cni/bin"
CNI_NET_DIR="/host/etc/cni/net.d"
KLOAK_CNI_CONF_DIR="/etc/kloak-cni/net.d" # Mounted ConfigMap

echo "Installing Kloak CNI..."

# 1. Copy Binary
echo "Copying kloak-cni to $CNI_BIN_DIR..."
cp /opt/cni/bin/kloak-cni $CNI_BIN_DIR/kloak-cni
chmod +x $CNI_BIN_DIR/kloak-cni

# 2. Find existing CNI config
# We pick the first lexicographical file in /etc/cni/net.d
CNI_CONF_FILE=$(ls -1 $CNI_NET_DIR | grep -E '\.conflist$' | head -n 1)

if [ -z "$CNI_CONF_FILE" ]; then
    # If no .conflist, look for .conf (and we'll need to convert it to a list)
    CNI_CONF_FILE=$(ls -1 $CNI_NET_DIR | grep -E '\.conf$' | head -n 1)
    if [ -z "$CNI_CONF_FILE" ]; then
        echo "No CNI configuration found in $CNI_NET_DIR. Waiting..."
        # Sleep and exit to let Kubernetes restart us? Or loop?
        # Better to loop.
        sleep 10
        exit 1
    fi
fi

echo "Found CNI config: $CNI_CONF_FILE"

# 3. Read Kloak CNI configuration snippet
# This assumes the ConfigMap mounts a file named "kloak-cni.conf" (or similar)
KLOAK_CONF_FILE="$KLOAK_CNI_CONF_DIR/kloak-cni.conf"
if [ ! -f "$KLOAK_CONF_FILE" ]; then
    echo "Kloak CNI config not found at $KLOAK_CONF_FILE"
    exit 1
fi

# 4. Inject Kloak CNI plugin
# Logic:
# - Read existing config
# - Check if "plugins" list exists (it should for .conflist)
# - If .conf, convert to .conflist with single plugin
# - Check if kloak-cni is already in the list to avoid duplicates
# - Append kloak-cni to the plugins list

# Helper to merge
# We use a temporary file to avoid partial writes
TMP_CONF="/tmp/cni.conf.tmp"

# Load snippet
KLOAK_PLUGIN=$(cat $KLOAK_CONF_FILE)

# Process
# If .conflist, we assume valid JSON with "plugins" array.
# If .conf, we wrap it in a list.

# Check extension
EXT="${CNI_CONF_FILE##*.}"

if [ "$EXT" = "conflist" ]; then
    cat "$CNI_NET_DIR/$CNI_CONF_FILE" | jq --argjson newplugin "$KLOAK_PLUGIN" '
        if .plugins | any(.type == "kloak-cni") then
            . # Already exists, do nothing (or update?)
        else
            .plugins += [$newplugin]
        end
    ' > $TMP_CONF
else
    # .conf file - convert to conflist
    cat "$CNI_NET_DIR/$CNI_CONF_FILE" | jq --argjson newplugin "$KLOAK_PLUGIN" '
        {
            cniVersion: .cniVersion,
            name: .name,
            plugins: [., $newplugin]
        }
    ' > $TMP_CONF
    
    # We must rename the file to .conflist for CNI to pick it up as a list?
    # Usually yes. But if we change the file name, we might leave the old one?
    # Standard practice: Replace the .conf with .conflist and remove .conf?
    # Required for chained plugins.
    mv "$CNI_NET_DIR/$CNI_CONF_FILE" "$CNI_NET_DIR/${CNI_CONF_FILE%.conf}.conflist.backup"
    CNI_CONF_FILE="${CNI_CONF_FILE%.conf}.conflist"
fi

# Move tmp file to target
mv $TMP_CONF "$CNI_NET_DIR/$CNI_CONF_FILE"

echo "Kloak CNI installed in $CNI_CONF_FILE"

# Sleep forever to keep Pod running (or exit if Job? DaemonSet usually sleeps)
# If we want to support "uninstall" on termination, we should handle signals.
echo "Sleeping..."
while true; do sleep 3600; done
