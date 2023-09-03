#!/usr/bin/env bash

set -euo pipefail

NATS_MAGIC_DOWNLOAD_URL="${NATS_MAGIC_DOWNLOAD_URL:-https://quarapublicstorage.blob.core.windows.net/releases/natsmagic}"

curl -fsSL "$NATS_MAGIC_DOWNLOAD_URL" --output /usr/local/bin/natsmagic

chmod +x /usr/local/bin/natsmagic

/usr/local/bin/natsmagic --version

if ! command -v  &> /dev/null
then
    echo "setcap command is not found, natsmagic will not be able to bind to port 443 without root permissions."
    exit
fi

setcap cap_net_bind_service=+ep /usr/local/bin/natsmagic
