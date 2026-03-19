import sqlite3
import math
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# 请将此处替换为你的实际 SQLite 数据库文件名
DATABASE = 'C:\\Users\\Cheng\\Desktop\\JScanner2\\Result\\Result_xfyun_cn_20260319.db'


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    # 使返回的行表现得像字典一样
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/data/<table>')
def get_table_data(table):
    # 安全白名单，防止 SQL 注入
    allowed_tables = ['ai_vulns', 'scan_results', 'sensitive_info']
    if table not in allowed_tables:
        return jsonify({'error': 'Invalid table name'}), 400

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    offset = (page - 1) * per_page

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # 获取总记录数
        cur.execute(f"SELECT COUNT(*) FROM {table}")
        total_records = cur.fetchone()[0]

        # 获取分页数据 (按 ID 倒序，最新发现的在最前)
        cur.execute(f"SELECT * FROM {table} ORDER BY id DESC LIMIT ? OFFSET ?", (per_page, offset))
        rows = cur.fetchall()

        data = [dict(row) for row in rows]

    except sqlite3.Error as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

    conn.close()

    return jsonify({
        'table': table,
        'data': data,
        'page': page,
        'per_page': per_page,
        'total_records': total_records,
        'total_pages': math.ceil(total_records / per_page)
    })


if __name__ == '__main__':
    app.run(debug=True, port=5000)
