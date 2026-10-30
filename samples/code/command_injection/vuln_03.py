from flask import Flask, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    expression = request.args.get("expr", "1+1")
    result = eval(expression)
    return str(result)
