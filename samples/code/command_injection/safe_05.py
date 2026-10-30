import ast

from flask import Flask, request

app = Flask(__name__)
OPS = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.Div: lambda a, b: a / b,
}


def evaluate(node):
    if isinstance(node, ast.Expression):
        return evaluate(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in OPS:
        return OPS[type(node.op)](evaluate(node.left), evaluate(node.right))
    raise ValueError("unsupported expression")


@app.route("/calc")
def calc():
    expression = request.args.get("expr", "1+1")
    try:
        result = evaluate(ast.parse(expression, mode="eval"))
    except (SyntaxError, ValueError, ZeroDivisionError):
        return "invalid expression", 400
    return str(result)
