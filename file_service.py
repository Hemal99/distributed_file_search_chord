# file_service.py
from flask import Flask, send_file, jsonify
import io, random, hashlib

def start_rest(port, node):
    app = Flask(__name__)

    @app.route('/download/<path:fname>', methods=['GET'])
    def download(fname):
        size = random.randint(2*1024*1024, 10*1024*1024)
        data = random.randbytes(size)
        hashv = hashlib.sha1(data).hexdigest()
        buf = io.BytesIO(data)
        buf.seek(0)
        print(f"Serving {fname} size={size} hash={hashv}")
        return send_file(buf, as_attachment=True, download_name=fname)

    app.run(host='0.0.0.0', port=port, threaded=True)
