from flask import Flask, Response, request
from markupsafe import escape

app = Flask(__name__)


@app.route("/comment")
def show_comment():
    content = request.args.get("content", "")
    return Response(f"<p>{escape(content)}</p>", mimetype="text/html")
