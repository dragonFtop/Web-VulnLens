import subprocess

from flask import Flask, request

app = Flask(__name__)
ALLOWED_HOSTS = {"127.0.0.1", "localhost"}


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    if host not in ALLOWED_HOSTS:
        return "invalid host", 400
    subprocess.run(["ping", "-c", "1", host], shell=False, check=False)
    return "done"
