"""
File Forensics — Flask backend
Analyzes uploaded files for format/extension mismatches.
No database required.
"""

import os
import uuid
import tempfile
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
from analyzer import analyze_file

app = Flask(__name__, static_folder='static')
CORS(app)

# 50 MB upload limit
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

UPLOAD_FOLDER = tempfile.mkdtemp(prefix='file_forensics_')


@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)


@app.route('/api/analyze', methods=['POST'])
def analyze():
    if 'files' not in request.files:
        return jsonify({'error': 'No files provided'}), 400

    uploaded = request.files.getlist('files')
    if not uploaded:
        return jsonify({'error': 'No files selected'}), 400

    results = []
    errors = []

    for f in uploaded:
        if f.filename == '':
            continue

        # Save to a temp path with a random name to avoid collisions
        original_name = f.filename
        safe_name = secure_filename(original_name) or 'upload'
        tmp_path = os.path.join(UPLOAD_FOLDER, f'{uuid.uuid4().hex}_{safe_name}')

        try:
            f.save(tmp_path)
            report = analyze_file(tmp_path, original_name)
            results.append(report)
        except Exception as exc:
            errors.append({'filename': original_name, 'error': str(exc)})
        finally:
            # Always clean up the temp file
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    if not results and errors:
        return jsonify({'error': 'All files failed to analyze', 'details': errors}), 500

    return jsonify({'results': results, 'errors': errors})


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'File Forensics'})


if __name__ == '__main__':
    print('File Forensics running at http://127.0.0.1:5000')
    app.run(debug=True, host='127.0.0.1', port=5000)
