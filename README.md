# Distributed Chord Content-Sharing System

## Overview

- Bootstrap UDP server: handles REG/UNREG.
- Chord nodes via `chord_node.py`: maintains finger tables, join, stabilize, search.
- `file_service.py`: REST endpoint to download random 2–10 MB file content.

## Run Instructions

Each command need to be run in a separate terminal.

```bash
python bootstrap_server.py
python chord_node.py 127.0.0.1 6001 7001 u1
python chord_node.py 127.0.0.1 6002 7002 u2
```

## Funtionalities avaialbe in Node CLI prompt

```bash
# Use CLI: `search <filename>`, `leave`, `files`
# Search files within network
search filename
# List files within node
files
# Leave the network
leave
```

### Ex- List all files from u1 server 


```bash
# Rest endpoint for node 1 is  listening on 7001 
# (According to this -> python chord_node.py 127.0.0.1 6001 7001 u1)
# Use below command in seperate terminal to see the Rest Endpoint output
curl 127.0.0.1:7001/files
```

### Output 

```
StatusCode        : 200
StatusDescription : OK
Content           : {"files":["Forrest_Gump.mkv","Toy_Story_3.mkv","Gladiator.mp4","Coco.mp4"]}

RawContent        : HTTP/1.1 200 OK
                    Connection: close
                    Content-Length: 76
                    Content-Type: application/json
                    Date: Fri, 25 Jul 2025 07:22:02 GMT
                    Server: Werkzeug/3.1.3 Python/3.13.5
```



## Search files inside Node

File Name - Gladiator.mp4

```bash
curl "http://127.0.0.1:7001/search?q=Gladiator."

# you don't have to mention full name of the file that you are searching

```

### Output

```
StatusCode        : 200
StatusDescription : OK
Content           : {"matched":["Gladiator.mp4"]}

RawContent        : HTTP/1.1 200 OK
                    Connection: close
                    Content-Length: 30
                    Content-Type: application/json
                    Date: Fri, 25 Jul 2025 08:50:12 GMT
                    Server: Werkzeug/3.1.3 Python/3.13.5

                    {"matched":["Gladiator.mp4"]}
```
