#!/bin/bash
cd "$(dirname "$0")"
echo "Omada API Hub - http://$(hostname -I | awk '{print $1}'):5000"
exec python3 app.py
