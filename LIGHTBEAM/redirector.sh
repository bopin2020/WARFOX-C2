#!/bin/bash

LOCAL_LISTENING_PORT=8888
C2_SERVER_IP=127.0.0.1
C2_SERVER_PORT=9999

echo "[+] Starting local redirector"
echo "[+] Current config: {Local port = $LOCAL_LISTENING_PORT, Remote Server:Port = $C2_SERVER_IP:$C2_SERVER_PORT}"

sudo socat -d -d TCP4-LISTEN:$LOCAL_LISTENING_PORT,fork TCP4:$C2_SERVER_IP:$C2_SERVER_PORT
