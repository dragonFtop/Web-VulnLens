from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/orders")
def list_orders():
    status = request.args.get("status", "open")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT id, total FROM orders WHERE status = '%s'" % status
    cursor.execute(query)
    return str(cursor.fetchall())
