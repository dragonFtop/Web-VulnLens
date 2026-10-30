from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    return render_template_string("<h1>Hello " + name + "</h1>")
