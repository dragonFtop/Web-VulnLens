import os
import shlex

from flask import Flask, request

app = Flask(__name__)


@app.route("/lookup")
def lookup():
    name = request.args.get("name", "")
    os.system("whois " + shlex.quote(name))
    return "ok"
