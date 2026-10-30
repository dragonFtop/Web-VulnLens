from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/welcome")
def welcome():
    name = request.args.get("name", "")
    return render_template("welcome.html", name=name)
