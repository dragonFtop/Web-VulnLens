from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/order")
def order_detail():
    order_id = int(request.args.get("id", "0"))
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT id, total FROM orders WHERE id = {order_id}")
    return str(cursor.fetchone())
