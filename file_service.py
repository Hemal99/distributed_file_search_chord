from flask import Flask, send_file, jsonify, request
import io, hashlib

def start_rest(port, node):
    app = Flask(__name__)

    @app.route('/download/<path:fname>', methods=['GET'])
    def download(fname):
        if fname not in node.files:
            return jsonify({"error": "File not found"}), 404

        try:
            return send_file(fname, as_attachment=True)
        except FileNotFoundError:
            return jsonify({"error": "File not found on disk"}), 404

        hashv = hashlib.sha1(data).hexdigest()
        buf = io.BytesIO(data)
        buf.seek(0)
        print(f"Serving {fname} size={len(data)} hash={hashv}")
        return send_file(buf, as_attachment=True, download_name=fname)

    @app.route('/files', methods=['GET'])
    def list_files():
        return jsonify({"files": list(node.files)})

    @app.route('/search', methods=['GET'])
    def search_files():
        query = request.args.get("q", "").lower()
        matched = [f for f in node.files if query in f.lower()]
        return jsonify({"matched": matched})

    app.run(host='0.0.0.0', port=port, threaded=True)
