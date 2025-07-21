# tests/test_search_rest.py
import threading, time, requests
from bootstrap_server import BootstrapServer
from chord_node import ChordNode

def test_search_and_download():
    threading.Thread(target=BootstrapServer().run, daemon=True).start()
    time.sleep(0.1)

    n1 = ChordNode('127.0.0.1', 6101, 7101, 'a1'); n1.start()
    n2 = ChordNode('127.0.0.1', 6102, 7102, 'a2'); n2.start()
    n3 = ChordNode('127.0.0.1', 6103, 7103, 'a3'); n3.start()
    time.sleep(1)

    filename = list(n2.files)[0]
    n1.search(filename)
    time.sleep(1)
    url = f"http://{n2.ip}:{n2.rest_port}/download/{filename}"
    r = requests.get(url)
    assert r.status_code == 200
    assert r.content  # received bytes
