"""
Тесты для SECURE MVP (порт 5001)
Запуск: JWT_SECRET_KEY=your_secret python test_secure.py
"""
import sys
import json
import threading
import time
import os

if not os.environ.get('JWT_SECRET_KEY'):
    print("ERROR: set JWT_SECRET_KEY environment variable first")
    print("  export JWT_SECRET_KEY='your_long_secret_here'")
    sys.exit(1)

sys.path.insert(0, 'app')
import main as app_module

app_module.init_db()
t = threading.Thread(
    target=lambda: app_module.app.run(host='127.0.0.1', port=5001, debug=False, use_reloader=False),
    daemon=True
)
t.start()
time.sleep(1.5)

import urllib.request

BASE = 'http://127.0.0.1:5001'


def post(path, data, token=None):
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        BASE + path, data=body, headers={'Content-Type': 'application/json'})
    if token:
        req.add_header('Authorization', f'Bearer {token}')
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read()), e.code


def get(path, token=None):
    req = urllib.request.Request(BASE + path)
    if token:
        req.add_header('Authorization', f'Bearer {token}')
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read()), e.code


def patch(path, data, token=None):
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        BASE + path, data=body, method='PATCH',
        headers={'Content-Type': 'application/json'})
    if token:
        req.add_header('Authorization', f'Bearer {token}')
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read()), e.code


results = []

# 1 Login engineer
r, c = post('/login', {'username': 'engineer1', 'password': 'engineer1'})
results.append(('LOGIN engineer1', c, c == 200 and 'token' in r, r.get('role')))
eng_token = r.get('token', '')

# 2 Login operator
r, c = post('/login', {'username': 'operator1', 'password': 'operator1'})
results.append(('LOGIN operator1', c, c == 200, r.get('role')))
op_token = r.get('token', '')

# 3 Equipment no auth → 401
r, c = get('/equipment')
results.append(('GET /equipment no auth → 401', c, c == 401, r.get('error', '')))

# 4 Equipment with auth → 200
r, c = get('/equipment', eng_token)
results.append(('GET /equipment with token → 200', c, c == 200, f'{len(r)} items'))

# 5 Create work order
r, c = post('/work-orders', {'equipment_id': 1, 'description': 'Плановое ТО насоса'}, eng_token)
results.append(('POST /work-orders (engineer) → 201', c, c == 201, r))

# 6 Update status
r, c = patch('/work-orders/1/status', {'status': 'in_progress'}, eng_token)
results.append(('PATCH status in_progress → 200', c, c == 200, r))

# 7 Invalid status → 400
r, c = patch('/work-orders/1/status', {'status': 'HACKED'}, eng_token)
results.append(('PATCH invalid status → 400', c, c == 400, r.get('error', '')))

# 8 Report engineer → 200
r, c = get('/report', eng_token)
results.append(('GET /report engineer → 200', c, c == 200, f'{len(r)} rows'))

# 9 Report operator → 403
r, c = get('/report', op_token)
results.append(('GET /report operator → 403', c, c == 403, r.get('error', '')))

# 10 Operator create order → 403
r, c = post('/work-orders', {'equipment_id': 1, 'description': 'x'}, op_token)
results.append(('POST /work-orders operator → 403', c, c == 403, r.get('error', '')))

# 11 SQL injection → 401
r, c = post('/login', {'username': "admin' --", 'password': 'x'})
results.append(('SQL injection → 401', c, c == 401, r.get('error', '')))

# 12 Wrong password → 401, neutral message
r, c = post('/login', {'username': 'engineer1', 'password': 'wrong'})
neutral = r.get('error', '') == 'Invalid credentials'
results.append(('Wrong password → neutral 401', c, c == 401 and neutral, r.get('error', '')))

# 13 Close unassigned order → 403
r, c = post('/work-orders/1/close', {}, eng_token)
results.append(('Close unassigned order → 403', c, c == 403, r.get('error', '')))

# 14 Assign engineer then close → 200
import sqlite3 as _sq
db = _sq.connect(app_module.DB_PATH)
db.execute("UPDATE work_orders SET assigned_to=2, status='in_progress' WHERE id=1")
db.commit(); db.close()

r, c = post('/work-orders/1/close', {}, eng_token)
results.append(('Close assigned order → 200', c, c == 200, r))

# 15 Description too long → 400
r, c = post('/work-orders', {'equipment_id': 1, 'description': 'A' * 501}, eng_token)
results.append(('Description too long → 400', c, c == 400, r.get('error', '')))

print()
print('РЕЗУЛЬТАТЫ ТЕСТОВ — SECURE MVP')
print('=' * 65)
for name, code, passed, detail in results:
    mark = '✓ PASS' if passed else '✗ FAIL'
    print(f'  {mark} [{code}] {name}')
    if not passed:
        print(f'          → {detail}')
print('=' * 65)
ok = sum(1 for _, _, p, _ in results if p)
print(f'Итог: {ok}/{len(results)} тестов прошли')
if ok == len(results):
    print('Все тесты успешно пройдены!')
