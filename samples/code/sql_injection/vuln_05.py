from flask import Flask, request
from sqlalchemy import create_engine, text

app = Flask(__name__)
engine = create_engine("sqlite:///app.db")


@app.route("/items")
def list_items():
    owner = request.args.get("owner", "")
    with engine.connect() as conn:
        rows = conn.execute(text(f"SELECT id FROM items WHERE owner = '{owner}'"))
    return str(rows.fetchall())
