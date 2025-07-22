# tests/test_chord.py
import pytest
from chord_node import ChordNode
import threading
import time

def test_simple_join():
    # start bootstrap
    from bootstrap_server import BootstrapServer
    threading.Thread(target=BootstrapServer().run, daemon=True).start()
    time.sleep(0.1)

    n1 = ChordNode('127.0.0.1', 6001, 7001, 'u1')
    n1.start()
    time.sleep(0.1)
    assert n1.predecessor is None
    assert n1.successor[2] == n1.id

    n2 = ChordNode('127.0.0.1', 6002, 7002, 'u2')
    n2.start()
    time.sleep(1)
    assert n2.successor[2] != n2.id
    assert n1.successor[2] != n1.id or n1.predecessor is not None
