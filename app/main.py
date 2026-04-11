"""
Oil & Gas Asset Maintenance MVP — SECURE VERSION
Вариант 2: Нефтегазовая отрасль - техническое обслуживание активов

Исправления по CWE:
  CWE-89  → параметризованные запросы
  CWE-916 → bcrypt вместо MD5
  CWE-798 → секрет из .env
  CWE-285 → проверка роли и владельца объекта
  CWE-306 → аутентификация на всех эндпоинтах
  CWE-209 → нейтральные сообщения об ошибках
  CWE-532 → чувствительные данные не пишутся в лог
  CWE-489 → debug=False, управляется переменной окружения
"""

import sqlite3
import logging
import os
import datetime
import re

import bcrypt
import jwt
from flask import Flask, request, jsonify, g
from functools import wraps

app = Flask(__name__)

# [FIX] CWE-798: секрет берётся из окружения; если не задан — ошибка при запуске
SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY environment variable is not set")

DB_PATH = os.environ.get("DB_PATH", "oil_gas_secure.db")

# [FIX] CWE-532 / CWE-489: логируем только безопасные данные, без debug-вывода секретов
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

ALLOWED_STATUSES = {"open", "in_progress", "on_hold", "closed"}
ALLOWED_ROLES = {"admin", "engineer", "operator"}


# ─── DB ────────────────────────────────────────────────────────────────────

def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','engineer','operator'))
        );
        CREATE TABLE IF NOT EXISTS equipment (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            location TEXT NOT NULL,
            status TEXT DEFAULT 'active' CHECK(status IN ('active','inactive','decommissioned'))
        );
        CREATE TABLE IF NOT EXISTS work_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            equipment_id INTEGER NOT NULL,
            description TEXT NOT NULL,
            status TEXT DEFAULT 'open' CHECK(status IN ('open','in_progress','on_hold','closed')),
            created_by INTEGER NOT NULL,
            assigned_to INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (equipment_id) REFERENCES equipment(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            entity TEXT,
            entity_id INTEGER,
            detail TEXT,
            ts TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)
    # [FIX] CWE-916: bcrypt вместо MD5
    users = [
        ("admin",     "admin123",   "admin"),
        ("engineer1", "engineer1",  "engineer"),
        ("operator1", "operator1",  "operator"),
    ]
    for username, raw_password, role in users:
        exists = cur.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
        if not exists:
            hashed = bcrypt.hashpw(raw_password.encode(), bcrypt.gensalt()).decode()
            cur.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                (username, hashed, role)
            )
    equipment_list = [
        ("Pump-01",       "Section A"),
        ("Valve-03",      "Section B"),
        ("Compressor-07", "Section C"),
    ]
    for name, loc in equipment_list:
        exists = cur.execute("SELECT 1 FROM equipment WHERE name=?", (name,)).fetchone()
        if not exists:
            cur.execute("INSERT INTO equipment (name, location) VALUES (?,?)", (name, loc))
    conn.commit()
    conn.close()


# ─── AUDIT ─────────────────────────────────────────────────────────────────

def audit(action, entity=None, entity_id=None, detail=None, user_id=None):
    """Пишет запись аудита в БД. Чувствительные данные сюда не передаются."""
    try:
        db = get_db()
        db.execute(
            "INSERT INTO audit_log (user_id, action, entity, entity_id, detail) VALUES (?,?,?,?,?)",
            (user_id, action, entity, entity_id, detail)
        )
        db.commit()
    except Exception as e:
        logger.error("audit write failed: %s", e)


# ─── AUTH HELPERS ──────────────────────────────────────────────────────────

def create_token(user_id: int, username: str, role: str) -> str:
    # FIX: токен с ограниченным сроком жизни (8 часов)
    payload = {
        "id":       user_id,
        "username": username,
        "role":     role,
        "exp":      datetime.datetime.utcnow() + datetime.timedelta(hours=8),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def require_auth(f):
    """Декоратор: проверяет токен и кладёт пользователя в g.current_user."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.removeprefix("Bearer ").strip()
        if not token:
            return jsonify({"error": "Authentication required"}), 401
        user = decode_token(token)
        if not user:
            return jsonify({"error": "Invalid or expired token"}), 401
        g.current_user = user
        return f(*args, **kwargs)
    return wrapper


def require_role(*roles):
    """Декоратор: проверяет роль после require_auth."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if g.current_user.get("role") not in roles:
                # [FIX] CWE-285: сервер проверяет роль; клиент не может её подменить
                logger.warning("Forbidden: user %s (role=%s) tried %s",
                               g.current_user.get("username"),
                               g.current_user.get("role"),
                               request.path)
                return jsonify({"error": "Forbidden"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ─── INPUT VALIDATION ──────────────────────────────────────────────────────

def validate_text(value, field_name: str, max_len: int = 255):
    if not value or not isinstance(value, str):
        return None, f"{field_name} is required"
    value = value.strip()
    if len(value) == 0:
        return None, f"{field_name} cannot be empty"
    if len(value) > max_len:
        return None, f"{field_name} too long (max {max_len})"
    return value, None


def validate_positive_int(value, field_name: str):
    try:
        v = int(value)
        if v <= 0:
            raise ValueError
        return v, None
    except (TypeError, ValueError):
        return None, f"{field_name} must be a positive integer"


# ─── AUTH ENDPOINTS ────────────────────────────────────────────────────────

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # FIX: валидация входных данных
    username = username.strip()[:64]
    if not username or not password:
        return jsonify({"error": "Invalid credentials"}), 401

    # [FIX] CWE-89: параметризованный запрос
    db = get_db()
    row = db.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username=?",
        (username,)
    ).fetchone()

    # [FIX] CWE-209: нейтральное сообщение — не раскрываем причину отказа
    if not row or not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        # [FIX] CWE-532: пароль НЕ пишем в лог
        logger.warning("Failed login attempt for username: %s", username)
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_token(row["id"], row["username"], row["role"])
    audit("LOGIN", user_id=row["id"])
    logger.info("User logged in: %s (role=%s)", row["username"], row["role"])
    return jsonify({"token": token, "role": row["role"]})


# ─── EQUIPMENT ──────────────────────────────────────────────────────────────

@app.route("/equipment", methods=["GET"])
@require_auth  # [FIX] CWE-306: теперь требует аутентификации
def list_equipment():
    db = get_db()
    rows = db.execute("SELECT id, name, location, status FROM equipment").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/equipment", methods=["POST"])
@require_auth
@require_role("admin", "engineer")  # [FIX] CWE-285: только admin и engineer
def add_equipment():
    data = request.get_json(silent=True) or {}
    name, err = validate_text(data.get("name"), "name", max_len=100)
    if err:
        return jsonify({"error": err}), 400
    location, err = validate_text(data.get("location"), "location", max_len=100)
    if err:
        return jsonify({"error": err}), 400

    # [FIX] CWE-89: параметризованный запрос
    db = get_db()
    cur = db.execute(
        "INSERT INTO equipment (name, location) VALUES (?,?)",
        (name, location)
    )
    db.commit()
    equipment_id = cur.lastrowid
    audit("ADD_EQUIPMENT", "equipment", equipment_id,
          f"name={name}", user_id=g.current_user["id"])
    logger.info("Equipment added: id=%d by user=%s", equipment_id, g.current_user["username"])
    return jsonify({"id": equipment_id, "name": name}), 201


# ─── WORK ORDERS ──────────────────────────────────────────────────────────

@app.route("/work-orders", methods=["POST"])
@require_auth
@require_role("admin", "engineer")
def create_work_order():
    data = request.get_json(silent=True) or {}
    equipment_id, err = validate_positive_int(data.get("equipment_id"), "equipment_id")
    if err:
        return jsonify({"error": err}), 400
    description, err = validate_text(data.get("description"), "description", max_len=500)
    if err:
        return jsonify({"error": err}), 400

    db = get_db()
    # Проверяем, что оборудование существует
    eq = db.execute("SELECT id FROM equipment WHERE id=?", (equipment_id,)).fetchone()
    if not eq:
        return jsonify({"error": "Equipment not found"}), 404

    cur = db.execute(
        "INSERT INTO work_orders (equipment_id, description, created_by) VALUES (?,?,?)",
        (equipment_id, description, g.current_user["id"])
    )
    db.commit()
    order_id = cur.lastrowid
    audit("CREATE_WORK_ORDER", "work_order", order_id,
          f"equipment_id={equipment_id}", user_id=g.current_user["id"])
    logger.info("Work order created: id=%d by user=%s", order_id, g.current_user["username"])
    return jsonify({"id": order_id}), 201


@app.route("/work-orders", methods=["GET"])
@require_auth  # [FIX] CWE-306
def list_work_orders():
    db = get_db()
    user = g.current_user

    # [FIX] CWE-285: operator видит только свои заявки
    if user["role"] == "operator":
        rows = db.execute(
            "SELECT id, equipment_id, description, status, created_at FROM work_orders WHERE assigned_to=?",
            (user["id"],)
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT id, equipment_id, description, status, created_at FROM work_orders"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/work-orders/<int:order_id>/status", methods=["PATCH"])
@require_auth
@require_role("admin", "engineer")  # [FIX] CWE-285: только engineer/admin
def update_status(order_id):
    data = request.get_json(silent=True) or {}
    new_status = data.get("status", "")

    # FIX: валидация допустимых значений статуса
    if new_status not in ALLOWED_STATUSES:
        return jsonify({"error": f"Invalid status. Allowed: {sorted(ALLOWED_STATUSES)}"}), 400

    db = get_db()
    order = db.execute("SELECT * FROM work_orders WHERE id=?", (order_id,)).fetchone()
    if not order:
        return jsonify({"error": "Work order not found"}), 404

    # [FIX] CWE-285: нельзя менять уже закрытую заявку
    if order["status"] == "closed":
        return jsonify({"error": "Cannot change status of a closed work order"}), 400

    db.execute("UPDATE work_orders SET status=? WHERE id=?", (new_status, order_id))
    db.commit()

    # [FIX] CWE-532: в лог только идентификаторы, не персданные
    audit("UPDATE_STATUS", "work_order", order_id,
          f"status={new_status}", user_id=g.current_user["id"])
    logger.info("Work order %d status → %s by %s", order_id, new_status, g.current_user["username"])
    return jsonify({"updated": True, "status": new_status})


@app.route("/work-orders/<int:order_id>/close", methods=["POST"])
@require_auth
@require_role("admin", "engineer")  # [FIX] CWE-285
def close_work_order(order_id):
    db = get_db()
    order = db.execute("SELECT * FROM work_orders WHERE id=?", (order_id,)).fetchone()
    if not order:
        return jsonify({"error": "Work order not found"}), 404

    # [FIX] CWE-285: engineer может закрывать только назначенные ему заявки
    user = g.current_user
    if user["role"] == "engineer" and order["assigned_to"] != user["id"]:
        return jsonify({"error": "Forbidden: not assigned to you"}), 403

    if order["status"] == "closed":
        return jsonify({"error": "Already closed"}), 400

    db.execute("UPDATE work_orders SET status='closed' WHERE id=?", (order_id,))
    db.commit()
    audit("CLOSE_WORK_ORDER", "work_order", order_id, user_id=user["id"])
    logger.info("Work order %d closed by %s", order_id, user["username"])
    return jsonify({"closed": True})


# ─── REPORT ──────────────────────────────────────────────────────────────

@app.route("/report", methods=["GET"])
@require_auth
@require_role("admin", "engineer")  # [FIX] CWE-285: operator не может экспортировать
def export_report():
    db = get_db()
    rows = db.execute("""
        SELECT wo.id, wo.description, wo.status, wo.created_at,
               e.name AS equipment_name,
               u.username AS created_by
        FROM work_orders wo
        JOIN equipment e ON e.id = wo.equipment_id
        JOIN users u ON u.id = wo.created_by
    """).fetchall()
    audit("EXPORT_REPORT", user_id=g.current_user["id"])
    # FIX: API не возвращает лишних полей (нет password_hash, нет внутренних id пользователей)
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    init_db()
    # [FIX] CWE-489: debug управляется переменной окружения, по умолчанию False
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, host="127.0.0.1", port=5001)
