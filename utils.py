# utils.py
import hashlib, struct
from config import MAX_ID 

def sha1_hash(key: str) -> int:
    return int(hashlib.sha1(key.encode()).hexdigest(), 16)

def in_interval(value, start, end, inclusive_right=False):
    if start < end:
        return start < value <= end if inclusive_right else start < value < end
    else:
        # interval wraps around max id space
        return value > start or value < end or (inclusive_right and value == end)


def format_message(body: str) -> str:
    """Prefix message body with its length in 4-digit format"""
    length = len(body) + 5  # +1 for space after length
    return f"{length:04} {body}"


def pack_msg(msg: str) -> bytes:
    body = msg.encode()
    return f"{len(body)+4:04d}".encode() + body

def unpack_msg(data: bytes) -> str:
    return data[4:].decode()


def numeric_id(ip, port):
    h = sha1_hash(f"{ip}:{port}")  # already int
    return h % MAX_ID
