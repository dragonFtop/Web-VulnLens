from flask import Flask, request
from markupsafe import Markup

app = Flask(__name__)


@app.route("/bio", methods=["POST"])
def save_bio():
    bio_text = request.form.get("bio", "")
    return Markup("<div class='bio'>" + bio_text + "</div>")
