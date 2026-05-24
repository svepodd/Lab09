from flask import Flask, request, make_response, jsonify
from markupsafe import escape
import sqlite3
import os
import subprocess
import json
import ast
import ipaddress
import logging

app = Flask(__name__)

# FIX (py-flask-debug-enabled / CWE-489): debug выключен.
# Управляется только через переменную окружения, по умолчанию False.
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

# FIX (py-hardcoded-credentials / CWE-798): секреты берём из окружения,
# в коде значений нет. Значения по умолчанию пустые.
DB_USER = os.environ.get("DB_USER", "")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
DB_PATH = os.environ.get("APP_DB_PATH", "app.db")

# Базовый уровень логирования — INFO (не DEBUG, чтобы не светить лишнее).
logging.basicConfig(level=logging.INFO)

# Каталог, из которого разрешено читать файлы (для /read).
SAFE_READ_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "files")
)
os.makedirs(SAFE_READ_DIR, exist_ok=True)


# FIX (ZAP 10038/10020/10021 и др.): добавляем security-заголовки ко всем ответам.
@app.after_request
def set_security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # FIX (ZAP 10036): не раскрываем версию сервера
    resp.headers["Server"] = "app"
    return resp


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


@app.route("/")
def index():
    # FIX (py-info-version-disclosure): не раскрываем версию приложения
    return "OK"


@app.route("/user")
def get_user():
    username = request.args.get("name", "")
    conn = get_db()
    cur = conn.cursor()
    # FIX (py-sql-injection / CWE-89): параметризованный запрос
    # вместо f-строки. Пользовательский ввод передаётся как параметр.
    rows = cur.execute(
        "SELECT id, name, email FROM users WHERE name = ?", (username,)
    ).fetchall()
    conn.close()
    return jsonify({"result": rows})


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # FIX (reflected XSS / CWE-79): экранируем пользовательский ввод
    html = f"<h1>Results for: {escape(q)}</h1>"
    return make_response(html, 200)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # FIX (py-command-injection / CWE-78): валидируем host как IP-адрес и
    # вызываем ping без shell, списком аргументов.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return "Invalid host", 400
    subprocess.run(
        ["ping", "-c", "1", host],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return f"Pinged {escape(host)}"


@app.route("/backup")
def backup():
    # FIX (py-command-injection / CWE-78): больше не вызываем shell.
    # Целевое имя жёстко фиксировано, пользовательский ввод не участвует
    # в формировании команды.
    target = "/tmp/backup.sql"
    subprocess.run(
        ["pg_dump", "mydb", "-f", target],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return f"Backup to {target} started"


@app.route("/read")
def read_file():
    name = request.args.get("path", "")
    # FIX (path traversal / CWE-22): разрешаем читать только внутри
    # SAFE_READ_DIR. Нормализуем путь и проверяем, что он не выходит за пределы.
    requested = os.path.abspath(os.path.join(SAFE_READ_DIR, name))
    if not requested.startswith(SAFE_READ_DIR + os.sep):
        return "Access denied", 403
    try:
        with open(requested, "r") as f:
            data = f.read()
        return make_response(f"<pre>{escape(data)}</pre>", 200)
    except Exception:
        return "Not found", 404


@app.route("/load")
def load():
    data = request.args.get("data", "")
    # FIX (py-insecure-deserialization / CWE-502): pickle заменён на json.
    # json не выполняет код при разборе.
    try:
        obj = json.loads(data)
        return jsonify({"loaded": obj})
    except Exception:
        return "Invalid JSON", 400


def _safe_calc(expr: str):
    # Безопасный вычислитель: только числа и арифметика, без eval.
    node = ast.parse(expr, mode="eval")
    allowed = (
        ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant,
        ast.Add, ast.Sub, ast.Mult, ast.Div, ast.USub, ast.UAdd,
    )
    for n in ast.walk(node):
        if not isinstance(n, allowed):
            raise ValueError("Unsupported expression")
        if isinstance(n, ast.Constant) and not isinstance(n.value, (int, float)):
            raise ValueError("Only numbers allowed")

    def _ev(n):
        if isinstance(n, ast.Expression):
            return _ev(n.body)
        if isinstance(n, ast.Constant):
            return n.value
        if isinstance(n, ast.UnaryOp):
            v = _ev(n.operand)
            return +v if isinstance(n.op, ast.UAdd) else -v
        a, b = _ev(n.left), _ev(n.right)
        if isinstance(n.op, ast.Add):
            return a + b
        if isinstance(n.op, ast.Sub):
            return a - b
        if isinstance(n.op, ast.Mult):
            return a * b
        return a / b

    return _ev(node)


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "1+1")
    # FIX (py-unsafe-eval / CWE-95): eval заменён на ограниченный
    # AST-вычислитель _safe_calc (только арифметика над числами).
    try:
        return str(_safe_calc(expr))
    except Exception:
        return "Invalid expression", 400


# FIX: debug-эндпоинт, раскрывавший окружение, удалён —
# он сливал переменные окружения (секреты, пути, токены).


if __name__ == "__main__":
    # host берём из окружения; debug управляется конфигом (по умолчанию off)
    app.run(host=os.environ.get("APP_HOST", "0.0.0.0"), port=8080)
