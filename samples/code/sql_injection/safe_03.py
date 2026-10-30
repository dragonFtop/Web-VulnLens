from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/batch", methods=["POST"])
def batch_insert():
    payload = request.get_json(silent=True) or {}
    names = payload.get("names", [])
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.executemany(
        "INSERT INTO tags(name) VALUES (?)", [(name,) for name in names]
    )
    conn.commit()
    return "ok"
