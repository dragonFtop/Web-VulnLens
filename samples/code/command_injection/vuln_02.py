import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/convert")
def convert():
    filename = request.args.get("file", "report.txt")
    subprocess.run("convert " + filename + " out.png", shell=True, check=False)
    return "ok"
