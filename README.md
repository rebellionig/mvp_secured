# Oil & Gas Asset Maintenance MVP — SECURE VERSION

Вариант 2: Нефтегазовая отрасль — техническое обслуживание активов  
Исправленная версия с устранёнными уязвимостями по CWE.

## Запуск

```bash
pip install -r requirements.txt

# Создайте .env из примера и задайте реальный секрет
cp .env.example .env
# Отредактируйте .env: укажите JWT_SECRET_KEY

python app/main.py
```

Сервер: http://localhost:5001

## Тестовые пользователи

| username    | password    | role      |
|-------------|-------------|-----------|
| admin       | admin123    | admin     |
| engineer1   | engineer1   | engineer  |
| operator1   | operator1   | operator  |

## Эндпоинты

| Метод  | URL                              | Роли                   | Описание                    |
|--------|----------------------------------|------------------------|-----------------------------|
| POST   | /login                           | —                      | Получить JWT-токен          |
| GET    | /equipment                       | all                    | Список оборудования         |
| POST   | /equipment                       | admin, engineer        | Добавить оборудование       |
| POST   | /work-orders                     | admin, engineer        | Создать заявку на ТО        |
| GET    | /work-orders                     | all (operator — свои)  | Список заявок               |
| PATCH  | /work-orders/<id>/status         | admin, engineer        | Изменить статус заявки      |
| POST   | /work-orders/<id>/close          | admin, engineer*       | Закрыть заявку              |
| GET    | /report                          | admin, engineer        | Экспорт отчёта              |

*engineer — только назначенные ему заявки

## Пример использования

```bash
# Логин
curl -X POST http://localhost:5001/login \
  -H "Content-Type: application/json" \
  -d '{"username":"engineer1","password":"engineer1"}'

# Получить оборудование (нужен токен)
curl http://localhost:5001/equipment \
  -H "Authorization: Bearer <TOKEN>"

# Создать заявку
curl -X POST http://localhost:5001/work-orders \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"equipment_id":1,"description":"Плановое ТО насоса"}'

# Сменить статус
curl -X PATCH http://localhost:5001/work-orders/1/status \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"status":"in_progress"}'

# Закрыть заявку
curl -X POST http://localhost:5001/work-orders/1/close \
  -H "Authorization: Bearer <TOKEN>"

# Экспорт отчёта
curl http://localhost:5001/report \
  -H "Authorization: Bearer <TOKEN>"
```

## Устранённые уязвимости

| CWE     | Описание                                   | Исправление                                      |
|---------|--------------------------------------------|--------------------------------------------------|
| CWE-89  | SQL-инъекция через конкатенацию строк      | Параметризованные запросы (?)                    |
| CWE-916 | Слабый алгоритм хеширования (MD5)          | bcrypt с автоматической солью                    |
| CWE-798 | Хардкод секретного ключа в коде            | Переменная окружения JWT_SECRET_KEY              |
| CWE-285 | Отсутствие объектной авторизации           | Проверка роли + владельца на каждом эндпоинте    |
| CWE-306 | Нет аутентификации на публичных эндпоинтах | Декоратор @require_auth на всех маршрутах        |
| CWE-209 | Раскрытие деталей в ошибках               | Нейтральные сообщения об ошибках                 |
| CWE-532 | Чувствительные данные в логах             | Логируем только id и действие, не пароли/токены  |
| CWE-489 | debug=True в продакшене                   | debug управляется FLASK_DEBUG из .env            |
