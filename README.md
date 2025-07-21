# Distributed Chord Content-Sharing System

## Overview

- Bootstrap UDP server: handles REG/UNREG.
- Chord nodes via `chord_node.py`: maintians finger tables, join, stabilize, search.
- `file_service.py`: REST endpoint to download random 2–10 MB file content.

## Run Instructions

```bash
python bootstrap_server.py
python chord_node.py 127.0.0.1 6001 7001 u1
python chord_node.py 127.0.0.1 6002 7002 u2
# Use CLI: `search <filename>`, `leave`, `files`
