"""Run from the project directory: python -m pytest -q.

Every test uses a separate temporary database. The shipped feedback.db is never
opened by the tests. A template avoids hashing four demo passwords for each case.
"""
import os
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.orm import sessionmaker

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
import main as m
from seed import SEED_TICKETS

PASSWORD = "ModusDemo123!"


def configure(path, monkeypatch):
    engine = m.build_engine(path)
    monkeypatch.setattr(m, "db_path", path)
    monkeypatch.setattr(m, "engine", engine)
    monkeypatch.setattr(m, "SessionLocal", sessionmaker(engine, expire_on_commit=False))
    return engine


@pytest.fixture(scope="session")
def template(tmp_path_factory):
    path = tmp_path_factory.mktemp("template") / "template.db"
    with pytest.MonkeyPatch.context() as patch:
        engine = configure(path, patch)
        patch.delenv("DEMO_PASSWORD", raising=False)
        m.init_db()
        engine.dispose()
    return path


@pytest.fixture
def app_db(tmp_path, monkeypatch, template):
    path = tmp_path / "test.db"
    with sqlite3.connect(template) as source, sqlite3.connect(path) as target:
        source.backup(target)
    engine = configure(path, monkeypatch)
    with TestClient(m.app) as client:
        yield client
    engine.dispose()


@pytest.fixture
def auth(app_db):
    clients = {}

    def sign_in(username):
        if username not in clients:
            client = TestClient(m.app)
            response = client.post("/auth/login", json={"username": username, "password": PASSWORD})
            assert response.status_code == 200, response.text
            client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
            clients[username] = client
        return clients[username]

    yield sign_in
    for client in clients.values():
        client.close()


def create(client, **updates):
    data = {"type": "Предложение", "category": "Обучение", "text": "Нужен практический семинар"}
    data.update(updates)
    response = client.post("/tickets", data=data)
    assert response.status_code == 201, response.text
    return response.json()


def test_homepage_local_styles(app_db):
    response = app_db.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "id=\"login-form\"" in response.text
    assert "cdn.jsdelivr.net" not in response.text and "cdn.tailwindcss" not in response.text
    assert "no-store" in response.headers["cache-control"]
    css = app_db.get("/tailwind.css")
    assert css.status_code == 200 and "text/css" in css.headers["content-type"]
    assert "tailwindcss v4.1.18" in css.text


@pytest.mark.parametrize("method,path,body", [
    ("GET", "/tickets", None), ("GET", "/tickets/1", None),
    ("GET", "/tickets/1/comments", None), ("GET", "/tickets/1/events", None),
    ("GET", "/analytics", None), ("GET", "/routing-rules", None),
    ("GET", "/metadata", None), ("GET", "/auth/me", None),
    ("GET", "/notifications", None), ("PATCH", "/notifications/1/read", None),
    ("POST", "/tickets", None), ("POST", "/auth/logout", None),
    ("PATCH", "/tickets/1", {"status": "В работе"}),
    ("POST", "/tickets/1/comments", {"text": "Уточнение"}),
    ("PATCH", "/routing-rules/1", {"is_primary_available": False}),
])
def test_anonymous_denied(app_db, method, path, body):
    assert app_db.request(method, path, json=body).status_code == 401


def test_login_logout_revokes_token(app_db):
    assert app_db.post("/auth/login", json={"username": "employee", "password": "wrong"}).status_code == 401
    assert app_db.post("/auth/login", json={"username": "missing", "password": "wrong"}).status_code == 401
    response = app_db.post("/auth/login", json={"username": "employee", "password": PASSWORD})
    assert response.status_code == 200
    assert response.json()["user"]["role"] == "employee"
    assert "password_hash" not in response.text
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    raw_token = app_db.cookies[m.COOKIE_NAME]
    with m.SessionLocal() as db:
        session = db.get(m.AuthSession, m.token_hash(raw_token))
        assert session is not None and session.token_hash != raw_token
    csrf = response.json()["csrf_token"]
    assert app_db.post("/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    assert app_db.get("/tickets", headers={"Cookie": f"{m.COOKIE_NAME}={raw_token}"}).status_code == 401


def test_argon2_hashes_and_account_ids(auth):
    assert auth("employee").get("/auth/me").json()["user"]["id"] != auth("employee2").get("/auth/me").json()["user"]["id"]
    with m.SessionLocal() as db:
        users = list(db.scalars(select(m.User)))
        assert len(users) == 4
        assert all(u.password_hash.startswith("$argon2id$") and PASSWORD not in u.password_hash for u in users)
        assert len({u.password_hash for u in users}) == 4


def test_csrf_and_cross_origin(auth):
    client = auth("employee")
    assert client.post("/tickets", data={"type": "Проблема", "category": "Обучение", "text": "Текст"}, headers={"X-CSRF-Token": ""}).status_code == 403
    assert client.post("/auth/logout", headers={"X-CSRF-Token": "bad"}).status_code == 403
    assert client.post("/auth/login", json={"username": "admin", "password": PASSWORD}, headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.get("/auth/me").status_code == 200


def test_expired_and_disabled_user(auth):
    client = auth("employee")
    with m.SessionLocal() as db:
        session = db.get(m.AuthSession, m.token_hash(client.cookies[m.COOKIE_NAME]))
        session.expires_at = m.utcnow() - timedelta(seconds=1)
        db.commit()
    assert client.get("/tickets").status_code == 401
    client = auth("employee2")
    with m.SessionLocal() as db:
        user = db.scalar(select(m.User).where(m.User.username == "employee2"))
        user.is_active = False
        db.commit()
    assert client.get("/tickets").status_code == 401
    assert client.post("/auth/login", json={"username": "employee2", "password": PASSWORD}).status_code == 401


def test_original_seed_metrics(auth):
    admin = auth("admin")
    rows = admin.get("/tickets").json()
    assert len(rows) == 20
    for source, actual in zip(SEED_TICKETS, rows):
        for field in ("code", "type", "category", "author_role", "priority", "status", "text", "assignee_role"):
            assert actual[field] == source[field]
        assert actual["author_id"] is None and actual["is_legacy"] is True
        assert datetime.fromisoformat(actual["created_at"]) < datetime.fromisoformat(actual["deadline_at"])
    assert [t["code"] for t in admin.get("/tickets?is_overdue=true").json()] == ["A-003", "A-009", "A-013"]
    result = admin.get("/analytics").json()
    assert result["total"] == 20
    assert result["by_type"] == {"Проблема": 9, "Предложение": 10, "Положительный отзыв": 1}
    assert result["completed_count"] == 3 and result["completed_percent"] == 15
    assert result["average_first_response_hours"] == 9.93 and result["first_response_sample_size"] == 15
    assert result["overdue_count"] == 3


def test_legacy_access_without_guessing_authors(auth):
    employee = auth("employee")
    assert employee.get("/tickets").json() == []
    assert employee.get("/tickets/1").status_code == 404
    manager = auth("manager")
    rows = manager.get("/tickets").json()
    assert len(rows) == 4 and all(t["department"] == "Закупки" for t in rows)
    assert manager.get("/tickets/3").status_code == 404
    assert manager.get("/tickets?scope=mine").json() == []


def test_employee_cannot_access_colleague_same_department(auth):
    owner, colleague = auth("employee"), auth("employee2")
    ticket = create(owner)
    other = create(colleague)
    assert [t["id"] for t in owner.get("/tickets").json()] == [ticket["id"]]
    assert owner.get(f"/tickets/{other['id']}").status_code == 404
    for suffix in ("comments", "events"):
        assert owner.get(f"/tickets/{other['id']}/{suffix}").status_code == 404
    assert owner.post(f"/tickets/{other['id']}/comments", json={"text": "Чужой"}).status_code == 404
    assert owner.patch(f"/tickets/{other['id']}", json={"status": "В работе"}).status_code == 403


@pytest.mark.parametrize("field,value", [("author_id", "4"), ("author_role", "Администратор"), ("role", "admin"), ("user_id", "4"), ("status", "Закрыто")])
def test_author_spoofing_rejected(auth, field, value):
    client = auth("employee")
    response = client.post("/tickets", data={"type": "Проблема", "category": "Обучение", "text": "Текст", field: value})
    assert response.status_code == 422
    assert client.get("/analytics").json()["total"] == 0


def test_auth_and_comment_spoofing(auth, app_db):
    employee = auth("employee")
    ticket = create(employee)
    assert employee.post(f"/tickets/{ticket['id']}/comments", json={"text": "А", "author_id": 4}).status_code == 422
    assert employee.post(f"/tickets/{ticket['id']}/comments", json={"text": "А", "author_role": "Админ"}).status_code == 422
    assert app_db.post("/auth/login", json={"username": "employee", "password": PASSWORD, "role": "admin"}).status_code == 422
    row = employee.post(f"/tickets/{ticket['id']}/comments", json={"text": "Ответ"}).json()
    assert row["author_id"] == ticket["author_id"] and row["author_role"] == "Сотрудник закупок"


def test_employee_cannot_manage(auth):
    employee = auth("employee")
    ticket = create(employee)
    assert employee.patch(f"/tickets/{ticket['id']}", json={"status": "В работе"}).status_code == 403
    assert employee.get("/routing-rules").status_code == 403
    assert employee.patch("/routing-rules/1", json={"is_primary_available": False}).status_code == 403
    assert employee.post("/tickets", data={"type": "Проблема", "category": "Обучение", "department": "Продажи", "text": "Текст"}).status_code == 403


def test_manager_department_boundary(auth):
    manager, admin = auth("manager"), auth("admin")
    own = create(auth("employee"))
    other = create(admin, department="Продажи")
    assert manager.get(f"/tickets/{own['id']}").status_code == 200
    for path in (f"/tickets/{other['id']}", f"/tickets/{other['id']}/comments", f"/tickets/{other['id']}/events"):
        assert manager.get(path).status_code == 404
    assert manager.patch(f"/tickets/{other['id']}", json={"status": "В работе"}).status_code == 404
    assert manager.post(f"/tickets/{other['id']}/comments", json={"text": "Текст"}).status_code == 404
    assert manager.get("/tickets?department=Продажи").json() == []
    assert manager.patch("/routing-rules/1", json={"primary_assignee": "Я"}).status_code == 403


def test_primary_fallback_and_existing_assignment(auth):
    admin = auth("admin")
    original = admin.get("/tickets/4").json()["assignee_role"]
    rule = next(r for r in admin.get("/routing-rules").json() if r["category"] == "Обучение")
    assert create(auth("employee"))["assignee_role"] == rule["primary_assignee"]
    response = admin.patch(f"/routing-rules/{rule['id']}", json={"primary_assignee": "Новый основной", "fallback_assignee": "Новый резерв", "is_primary_available": False})
    assert response.status_code == 200
    assert create(auth("employee"))["assignee_role"] == "Новый резерв"
    admin.patch(f"/routing-rules/{rule['id']}", json={"is_primary_available": True})
    assert create(auth("employee"))["assignee_role"] == "Новый основной"
    assert admin.get("/tickets/4").json()["assignee_role"] == original


@pytest.mark.parametrize("status,ticket_id", [("Закрыто", 1), ("Отклонено", 1), ("Реализовано", 3)])
@pytest.mark.parametrize("resolution", [None, "", "   "])
def test_final_requires_resolution(auth, status, ticket_id, resolution):
    admin = auth("admin")
    before = admin.get(f"/tickets/{ticket_id}").json()
    response = admin.patch(f"/tickets/{ticket_id}", json={"status": status, "final_resolution": resolution})
    assert response.status_code == 422
    assert admin.get(f"/tickets/{ticket_id}").json() == before


def test_transitions_first_response_and_audit(auth):
    employee, manager = auth("employee"), auth("manager")
    ticket = create(employee)
    path = f"/tickets/{ticket['id']}"
    assert manager.patch(path, json={"status": "Реализовано", "final_resolution": "Рано"}).status_code == 422
    assert employee.post(path + "/comments", json={"text": "Добавляю детали"}).status_code == 201
    assert manager.get(path).json()["first_response_at"] is None
    response = manager.patch(path, json={"status": "Ожидает уточнения", "assignee_role": "Руководитель закупок"})
    assert response.status_code == 200
    first = response.json()["first_response_at"]
    assert first is not None
    assert employee.post(path + "/comments", json={"text": "Уточнение от автора"}).status_code == 201
    assert manager.patch(path, json={"status": "В работе"}).status_code == 200
    response = manager.patch(path, json={"status": "Реализовано", "final_resolution": "Провели семинар"})
    assert response.status_code == 200
    assert response.json()["first_response_at"] == first
    assert manager.patch(path, json={"final_resolution": None}).status_code == 422
    assert manager.patch(path, json={"final_resolution": "Провели два семинара"}).status_code == 200
    assert manager.patch(path, json={"status": "Новое"}).status_code == 422
    assert manager.patch(path, json={"status": "В работе"}).json()["first_response_at"] == first
    events = employee.get(path + "/events").json()
    actions = [e["action"] for e in events]
    assert actions.count("created") == 1 and actions.count("status_changed") == 4
    assert actions.count("assignee_changed") == 1 and actions.count("resolution_changed") == 2
    event = next(e for e in events if e["action"] == "assignee_changed")
    assert event["old_value"] == "Ответственный за обучение" and event["new_value"] == "Руководитель закупок"
    assert all(e["actor_id"] and e["actor_name"] and e["created_at"].endswith("Z") for e in events)


def test_scoped_analytics_and_rejected_definition(auth):
    employee, manager, admin = auth("employee"), auth("manager"), auth("admin")
    assert employee.get("/analytics").json()["average_first_response_hours"] is None
    create(employee)
    create(auth("employee2"))
    create(admin, department="Продажи")
    assert employee.get("/analytics").json()["total"] == 1
    assert manager.get("/analytics").json()["total"] == 6
    assert admin.get("/analytics").json()["total"] == 23
    assert manager.get("/analytics?scope=mine").json()["total"] == 0
    with m.SessionLocal() as db:
        rejected = db.get(m.Ticket, 17)
        rejected.deadline_at = m.utcnow() - timedelta(hours=1)
        db.commit()
    assert admin.get("/tickets/17").json()["is_overdue"] is True
    assert admin.get("/analytics").json()["completed_count"] == 3


def test_filters_file_and_sla(auth):
    admin = auth("admin")
    assert [r["code"] for r in admin.get("/tickets", params={"department": "Закупки", "category": "Обучение", "status": "Реализовано"}).json()] == ["A-004"]
    assert len(admin.get("/tickets?is_overdue=false").json()) == 17
    employee = auth("employee")
    response = employee.post("/tickets", data={"type": "Проблема", "category": "Обучение", "text": "Пример", "priority": "Высокий"}, files={"file": ("../test.txt", b"test", "text/plain")})
    assert response.status_code == 201
    row = response.json()
    assert row["attachment_name"] == "test.txt" and row["department"] == "Закупки"
    assert datetime.fromisoformat(row["deadline_at"]) - datetime.fromisoformat(row["created_at"]) == timedelta(hours=48)


def test_concurrent_unique_codes(auth):
    employee = auth("employee")
    with ThreadPoolExecutor(max_workers=6) as pool:
        responses = list(pool.map(lambda _: employee.post("/tickets", data={"type": "Проблема", "category": "Обучение", "text": "Одновременно"}), range(8)))
    assert all(r.status_code == 201 for r in responses)
    assert len({r.json()["code"] for r in responses}) == 8


def test_validation_and_no_partial_writes(auth):
    employee, admin = auth("employee"), auth("admin")
    for data in ({"type": "Неизвестно", "category": "Обучение", "text": "А"}, {"type": "Проблема", "category": "Нет", "text": "А"}, {"type": "Проблема", "category": "Обучение", "text": "   "}):
        assert employee.post("/tickets", data=data).status_code == 422
    assert employee.get("/tickets").json() == []
    assert admin.patch("/routing-rules/1", json={"primary_assignee": "   "}).status_code == 422
    assert admin.patch("/routing-rules/1", json={"is_primary_available": None}).status_code == 422
    assert admin.patch("/tickets/1", json={"author_id": 4}).status_code == 422
    assert admin.get("/tickets/999").status_code == 404
    assert admin.patch("/routing-rules/999", json={"is_primary_available": False}).status_code == 404
    assert admin.get("/analytics?top_limit=0").status_code == 422


def test_repeat_start_preserves_new_data(auth):
    employee = auth("employee")
    ticket = create(employee)
    employee.post(f"/tickets/{ticket['id']}/comments", json={"text": "Не потерять"})
    manager = auth("manager")
    manager.patch(f"/tickets/{ticket['id']}", json={"status": "В работе"})
    manager.patch(f"/tickets/{ticket['id']}", json={"status": "Реализовано", "final_resolution": "Сохранённый итог"})
    admin = auth("admin")
    admin.patch("/routing-rules/1", json={"is_primary_available": False})
    before_events = employee.get(f"/tickets/{ticket['id']}/events").json()
    m.init_db()
    assert employee.get(f"/tickets/{ticket['id']}").json()["author_id"] == ticket["author_id"]
    assert employee.get(f"/tickets/{ticket['id']}").json()["final_resolution"] == "Сохранённый итог"
    assert employee.get(f"/tickets/{ticket['id']}/comments").json()[0]["text"] == "Не потерять"
    assert employee.get(f"/tickets/{ticket['id']}/events").json() == before_events
    assert admin.get("/routing-rules").json()[0]["is_primary_available"] is False
    with m.SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(m.User)) == 4
        assert db.scalar(text("PRAGMA foreign_keys")) == 1


def test_migration_backup_every_original_value(tmp_path, monkeypatch, template):
    path = tmp_path / "legacy.db"
    # Recreate the three actual legacy tables without new author ids or auth tables.
    original = {}
    with sqlite3.connect(template) as source, sqlite3.connect(path) as legacy:
        for table in ("tickets", "comments", "routing_rules"):
            columns = [(r[1], r[2]) for r in source.execute(f"PRAGMA table_info({table})") if r[1] != "author_id"]
            definitions = ','.join(f'"{name}" {kind}' + (' PRIMARY KEY' if name == 'id' else '') for name, kind in columns)
            legacy.execute(f"CREATE TABLE {table} ({definitions})")
            names = ','.join(f'"{name}"' for name, _ in columns)
            rows = source.execute(f"SELECT {names} FROM {table} ORDER BY id").fetchall()
            legacy.executemany(f"INSERT INTO {table} VALUES ({','.join('?' for _ in columns)})", rows)
            original[table] = (names, rows)
        # Existing incomplete final state must not be rewritten by the new policy.
        legacy.execute("UPDATE tickets SET final_resolution=NULL WHERE id=4")
    with sqlite3.connect(path) as db:
        original['tickets'] = (original['tickets'][0], db.execute(f"SELECT {original['tickets'][0]} FROM tickets ORDER BY id").fetchall())
    engine = configure(path, monkeypatch)
    m.init_db()
    backups = list((tmp_path / "backups").glob("*.db"))
    assert len(backups) == 1
    for inspected in (path, backups[0]):
        with sqlite3.connect(inspected) as connection:
            for table, (names, rows) in original.items():
                assert connection.execute(f"SELECT {names} FROM {table} ORDER BY id").fetchall() == rows
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT count(*) FROM tickets WHERE author_id IS NOT NULL").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM ticket_events WHERE action='imported'").fetchone()[0] == 20
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    m.init_db()
    assert len(list((tmp_path / "backups").glob("*.db"))) == 1
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT count(*) FROM ticket_events").fetchone()[0] == 20
    engine.dispose()


def test_notifications_assignment_clarification_resolution(auth):
    employee, colleague, manager, admin = auth("employee"), auth("employee2"), auth("manager"), auth("admin")
    ticket = create(employee)
    path = f"/tickets/{ticket['id']}"
    notices = manager.get("/notifications").json()
    assert len(notices) == 1 and notices[0]["kind"] == "assignment"
    assert admin.get("/notifications").json()[0]["kind"] == "assignment"
    assert employee.get("/notifications").json() == []
    manager.patch(path, json={"status": "Ожидает уточнения"})
    notices = employee.get("/notifications").json()
    assert len(notices) == 1 and notices[0]["kind"] == "clarification"
    assert colleague.get("/notifications").json() == []
    assert colleague.patch(f"/notifications/{notices[0]['id']}/read").status_code == 404
    assert employee.patch(f"/notifications/{notices[0]['id']}/read").status_code == 200
    assert employee.get("/notifications?unread_only=true").json() == []
    manager.patch(path, json={"status": "Реализовано", "final_resolution": "Семинар проведён"})
    result = employee.get("/notifications").json()
    assert len(result) == 2 and result[0]["kind"] == "resolution" and "Семинар проведён" in result[0]["message"]


def test_notifications_do_not_bypass_ticket_scope(auth):
    employee, manager = auth("employee"), auth("manager")
    ticket = create(employee)
    assert len(manager.get("/notifications").json()) == 1
    with m.SessionLocal() as db:
        db.get(m.Ticket, ticket["id"]).department = "Продажи"
        db.commit()
    assert manager.get("/notifications").json() == []


def test_untrusted_role_cookie_headers_and_queries(auth):
    employee = auth("employee")
    own = create(employee)
    rows = employee.get("/tickets", params={"role": "admin", "author_id": 4}, headers={"X-Role": "admin"}).json()
    assert [t["id"] for t in rows] == [own["id"]]
    assert employee.get("/routing-rules", headers={"X-Role": "admin"}).status_code == 403
    with TestClient(m.app) as fake:
        fake.cookies.set(m.COOKIE_NAME, "admin")
        assert fake.get("/tickets").status_code == 401
