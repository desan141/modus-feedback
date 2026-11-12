"""Модус · Голос команды. Request -> user -> access scope -> transaction.

Run python main.py. Migration is in migrations.py; runnable checks in tests/.
"""
from __future__ import annotations

import hashlib
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, PlainSerializer, ValidationError, field_validator
from pwdlib import PasswordHash
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, create_engine, delete, event, func, select, text as sql_text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from starlette.datastructures import UploadFile

from migrations import migrate_database

ROOT = Path(__file__).resolve().parent
COOKIE_NAME = "modus_session"
SESSION_HOURS = 8
SECURE_COOKIE = os.getenv("SECURE_COOKIES", "0") == "1"
PASSWORDS = PasswordHash.recommended()  # Argon2id, with a fresh random salt.
DUMMY_HASH = PASSWORDS.hash("unused-constant-time-password")


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(value: datetime) -> str:
    return value.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


UTCTime = Annotated[datetime, PlainSerializer(iso, return_type=str)]


class TicketType(str, Enum):
    problem = "Проблема"
    suggestion = "Предложение"
    positive = "Положительный отзыв"


class TicketStatus(str, Enum):
    new = "Новое"
    review = "На рассмотрении"
    working = "В работе"
    clarification = "Ожидает уточнения"
    implemented = "Реализовано"
    rejected = "Отклонено"
    closed = "Закрыто"


Role = Literal["employee", "manager", "admin"]
Priority = Literal["Низкий", "Средний", "Высокий"]
COMPLETED = ("Закрыто", "Реализовано")
FINAL_STATUSES = (*COMPLETED, "Отклонено")
SLA_HOURS = {"Высокий": 48, "Средний": 120, "Низкий": 240}
TRANSITIONS = {
    "Новое": ["На рассмотрении", "В работе", "Ожидает уточнения", "Отклонено", "Закрыто"],
    "На рассмотрении": ["В работе", "Ожидает уточнения", "Реализовано", "Отклонено", "Закрыто"],
    "В работе": ["На рассмотрении", "Ожидает уточнения", "Реализовано", "Отклонено", "Закрыто"],
    "Ожидает уточнения": ["На рассмотрении", "В работе", "Реализовано", "Отклонено", "Закрыто"],
    "Реализовано": ["В работе"], "Отклонено": ["В работе"], "Закрыто": ["В работе"],
}
DEMO_USERS = [
    ("employee", "Анна · сотрудник закупок", "employee", "Закупки", "Сотрудник закупок"),
    ("employee2", "Илья · сотрудник закупок", "employee", "Закупки", "Сотрудник закупок"),
    ("manager", "Мария · руководитель закупок", "manager", "Закупки", "Руководитель закупок"),
    ("admin", "Администратор демо", "admin", "Управление", "Администратор системы"),
]


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True)
    display_name: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(20))
    department: Mapped[str] = mapped_column(String(150))
    author_role: Mapped[str] = mapped_column(String(200))
    password_hash: Mapped[str] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    csrf_token: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)


class Ticket(Base):
    __tablename__ = "tickets"
    __table_args__ = {"sqlite_autoincrement": True}
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(30), unique=True)
    type: Mapped[str] = mapped_column(String(40))
    category: Mapped[str] = mapped_column(String(150), index=True)
    department: Mapped[str] = mapped_column(String(150), index=True)
    author_role: Mapped[str] = mapped_column(String(200))
    author_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    priority: Mapped[str] = mapped_column(String(20), default="Средний")
    status: Mapped[str] = mapped_column(String(40), default="Новое", index=True)
    text: Mapped[str] = mapped_column(Text)
    assignee_role: Mapped[str] = mapped_column(String(200))
    fallback_assignee_role: Mapped[str] = mapped_column(String(200))
    final_resolution: Mapped[str | None] = mapped_column(Text)
    attachment_name: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    first_response_at: Mapped[datetime | None] = mapped_column(DateTime)
    deadline_at: Mapped[datetime] = mapped_column(DateTime, index=True)


class Comment(Base):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), index=True)
    author_role: Mapped[str] = mapped_column(String(200))
    author_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class RoutingRule(Base):
    __tablename__ = "routing_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    category: Mapped[str] = mapped_column(String(150), unique=True)
    primary_assignee: Mapped[str] = mapped_column(String(200))
    fallback_assignee: Mapped[str] = mapped_column(String(200))
    is_primary_available: Mapped[bool] = mapped_column(Boolean, default=True)


class TicketEvent(Base):
    __tablename__ = "ticket_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey("tickets.id"), index=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    actor_name: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(40))
    old_value: Mapped[str | None] = mapped_column(Text)
    new_value: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AppMeta(Base):
    __tablename__ = "app_meta"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[int] = mapped_column(primary_key=True)
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey("tickets.id"), index=True)
    kind: Mapped[str] = mapped_column(String(30))
    message: Mapped[str] = mapped_column(Text)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


def build_engine(path: Path):
    result = create_engine("sqlite:///" + path.as_posix(), connect_args={"check_same_thread": False, "timeout": 30})

    @event.listens_for(result, "connect")
    def sqlite_settings(connection, _):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()

    return result


db_path = Path(os.getenv("DB_PATH", str(ROOT / "feedback.db"))).resolve()
engine = build_engine(db_path)
SessionLocal = sessionmaker(engine, expire_on_commit=False)


def init_db():
    from seed import seed_database

    db_path.parent.mkdir(parents=True, exist_ok=True)
    backup = migrate_database(db_path)
    if backup:
        print(f"Резервная копия перед миграцией: {backup}", flush=True)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        db.execute(sql_text("BEGIN IMMEDIATE"))
        if db.get(AppMeta, "seeded") is None:
            seed_database(db, Ticket, Comment, RoutingRule, utcnow())
            db.add(AppMeta(key="seeded", value="1"))
        for username, display, role, department, author_role in DEMO_USERS:
            if db.scalar(select(User).where(User.username == username)) is None:
                db.add(User(username=username, display_name=display, role=role, department=department,
                            author_role=author_role, password_hash=PASSWORDS.hash(os.getenv("DEMO_PASSWORD", "ModusDemo123!"))))
        db.flush()
        if db.get(AppMeta, "legacy_events") is None:
            for ticket in db.scalars(select(Ticket).where(Ticket.author_id.is_(None))):
                db.add(TicketEvent(ticket_id=ticket.id, actor_id=None, actor_name="Миграция",
                                   action="imported", new_value="Историческая запись; личность автора не установлена"))
            db.add(AppMeta(key="legacy_events", value="1"))
        db.execute(sql_text("PRAGMA user_version=2"))
        db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield
    engine.dispose()


app = FastAPI(title="Модус · Голос команды", version="2.0.0", lifespan=lifespan)
ALLOWED_ORIGINS = [s.strip() for s in os.getenv("CORS_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000").split(",") if s.strip()]
if "*" in ALLOWED_ORIGINS:
    raise RuntimeError("Для сессий укажите конкретные CORS_ORIGINS, без *")
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True,
                   allow_methods=["GET", "POST", "PATCH", "OPTIONS"], allow_headers=["Content-Type", "X-CSRF-Token"])


@app.middleware("http")
async def browser_security(request: Request, call_next):
    if request.method in ("POST", "PATCH", "PUT", "DELETE"):
        origin = request.headers.get("origin")
        if origin and origin not in [str(request.base_url).rstrip("/"), *ALLOWED_ORIGINS]:
            return JSONResponse({"detail": "Запрос с другого сайта запрещён"}, status_code=403)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'" if request.url.path == "/" else "frame-ancestors 'none'"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/", response_class=FileResponse, include_in_schema=False)
def web_interface():
    return FileResponse(ROOT / "index.html", media_type="text/html")


@app.get("/tailwind.css", response_class=FileResponse, include_in_schema=False)
def local_styles():
    return FileResponse(ROOT / "tailwind.css", media_type="text/css")


def get_db():
    with SessionLocal() as db:
        yield db


DB = Annotated[Session, Depends(get_db)]


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def current_user(request: Request, db: DB) -> User:
    token = request.cookies.get(COOKIE_NAME, "")
    session = db.get(AuthSession, token_hash(token)) if token else None
    user = db.get(User, session.user_id) if session and session.expires_at > utcnow() else None
    if user is None or not user.is_active:
        raise HTTPException(401, "Войдите в аккаунт. Сессия отсутствует или истекла.")
    request.state.auth_session = session
    return user


CurrentUser = Annotated[User, Depends(current_user)]


def write_user(request: Request, user: CurrentUser,
               csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None) -> User:
    csrf = csrf_token or ""
    if not csrf or not secrets.compare_digest(csrf, request.state.auth_session.csrf_token):
        raise HTTPException(403, "Проверка сессии не пройдена. Обновите страницу и повторите действие.")
    return user


Writer = Annotated[User, Depends(write_user)]


def require_admin(user: User):
    if user.role != "admin":
        raise HTTPException(403, "Только администратор может управлять маршрутизацией")


def require_manager(user: User):
    if user.role not in ("manager", "admin"):
        raise HTTPException(403, "Изменять статус, ответственного и решение может руководитель или администратор")


def accessible_tickets(user: User, mine: bool = False):
    query = select(Ticket)
    if mine or user.role == "employee":
        return query.where(Ticket.author_id == user.id)
    if user.role == "manager":
        return query.where(Ticket.department == user.department)
    return query


def require_ticket(db: Session, user: User, ticket_id: int) -> Ticket:
    ticket = db.scalar(accessible_tickets(user).where(Ticket.id == ticket_id))
    if ticket is None:
        raise HTTPException(404, "Обращение не найдено или недоступно для вашей учётной записи")
    return ticket


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LoginInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    display_name: str
    role: Role
    department: str
    author_role: str


class TicketCreate(InputModel):
    type: TicketType
    category: str = Field(min_length=1, max_length=150)
    department: str | None = Field(default=None, min_length=1, max_length=150)
    priority: Priority = "Средний"
    text: str = Field(min_length=1, max_length=20000)


class TicketPatch(InputModel):
    status: TicketStatus | None = None
    assignee_role: str | None = Field(default=None, min_length=1, max_length=200)
    final_resolution: str | None = Field(default=None, max_length=20000)

    @field_validator("status", "assignee_role")
    @classmethod
    def no_explicit_null(cls, value):
        if value is None:
            raise ValueError("Поле не может быть null; пропустите его, чтобы оставить без изменения")
        return value


class CommentCreate(InputModel):
    text: str = Field(min_length=1, max_length=20000)


class RoutingPatch(InputModel):
    primary_assignee: str | None = Field(default=None, min_length=1, max_length=200)
    fallback_assignee: str | None = Field(default=None, min_length=1, max_length=200)
    is_primary_available: bool | None = None

    @field_validator("primary_assignee", "fallback_assignee", "is_primary_available")
    @classmethod
    def no_explicit_null(cls, value):
        if value is None:
            raise ValueError("Поле не может быть null")
        return value


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class CommentOut(ORMModel):
    id: int
    ticket_id: int
    author_id: int | None
    author_role: str
    text: str
    created_at: UTCTime


class TicketOut(ORMModel):
    id: int
    code: str
    type: TicketType
    category: str
    department: str
    author_id: int | None
    author_role: str
    priority: Priority
    status: TicketStatus
    text: str
    assignee_role: str
    fallback_assignee_role: str
    final_resolution: str | None
    attachment_name: str | None
    created_at: UTCTime
    first_response_at: UTCTime | None
    deadline_at: UTCTime
    is_overdue: bool = False
    is_legacy: bool = False
    allowed_statuses: list[str] = Field(default_factory=list)


class EventOut(ORMModel):
    id: int
    ticket_id: int
    actor_id: int | None
    actor_name: str
    action: str
    old_value: str | None
    new_value: str | None
    created_at: UTCTime


class RoutingOut(ORMModel):
    id: int
    category: str
    primary_assignee: str
    fallback_assignee: str
    is_primary_available: bool


def ticket_out(ticket: Ticket, user: User, now: datetime | None = None) -> TicketOut:
    result = TicketOut.model_validate(ticket)
    result.is_overdue = ticket.deadline_at < (now or utcnow()) and ticket.status not in COMPLETED
    result.is_legacy = ticket.author_id is None
    result.allowed_statuses = [ticket.status, *TRANSITIONS.get(ticket.status, [])] if user.role != "employee" else []
    return result


@app.post("/auth/login")
def login(data: LoginInput, response: Response, request: Request, db: DB):
    user = db.scalar(select(User).where(User.username == data.username.strip().lower()))
    valid = PASSWORDS.verify(data.password, user.password_hash if user else DUMMY_HASH)
    if not user or not valid or not user.is_active:
        raise HTTPException(401, "Неверный логин или пароль")
    previous = request.cookies.get(COOKIE_NAME)
    if previous:
        db.execute(delete(AuthSession).where(AuthSession.token_hash == token_hash(previous)))
    db.execute(delete(AuthSession).where(AuthSession.expires_at <= utcnow()))
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    db.add(AuthSession(token_hash=token_hash(token), user_id=user.id, csrf_token=csrf,
                       expires_at=utcnow() + timedelta(hours=SESSION_HOURS)))
    db.commit()
    response.set_cookie(COOKIE_NAME, token, max_age=SESSION_HOURS * 3600, httponly=True,
                        secure=SECURE_COOKIE, samesite="strict", path="/")
    return {"user": UserOut.model_validate(user), "csrf_token": csrf}


@app.get("/auth/me")
def me(user: CurrentUser, request: Request):
    return {"user": UserOut.model_validate(user), "csrf_token": request.state.auth_session.csrf_token}


@app.post("/auth/logout")
def logout(user: Writer, request: Request, response: Response, db: DB):
    db.delete(request.state.auth_session)
    db.commit()
    response.delete_cookie(COOKIE_NAME, path="/", secure=SECURE_COOKIE, httponly=True, samesite="strict")
    return {"detail": "Вы вышли из аккаунта"}


@app.get("/metadata")
def metadata(user: CurrentUser, db: DB):
    departments = [user.department]
    if user.role == "admin":
        departments = sorted(set(db.scalars(select(Ticket.department))) | {"Закупки", "Продажи", "Проектирование", "Проектный отдел", "Бухгалтерия", "Офис", "IT", "Сервис", user.department})
    return {"categories": list(db.scalars(select(RoutingRule.category).order_by(RoutingRule.category))),
            "departments": departments, "statuses": list(TRANSITIONS), "transitions": TRANSITIONS, "sla_hours": SLA_HOURS}


@app.get("/tickets", response_model=list[TicketOut])
def list_tickets(db: DB, user: CurrentUser, department: str | None = None, category: str | None = None,
                 status: TicketStatus | None = None, is_overdue: bool | None = None,
                 scope: Literal["accessible", "mine"] = "accessible"):
    now = utcnow()
    query = accessible_tickets(user, scope == "mine")
    for column, value in ((Ticket.department, department), (Ticket.category, category), (Ticket.status, status)):
        if value is not None:
            query = query.where(column == value)
    overdue = (Ticket.deadline_at < now) & Ticket.status.not_in(COMPLETED)
    if is_overdue is not None:
        query = query.where(overdue if is_overdue else ~overdue)
    return [ticket_out(ticket, user, now) for ticket in db.scalars(query.order_by(Ticket.id))]


# Explicit OpenAPI schema keeps the multipart form usable in Swagger.
CREATE_SCHEMA = {"requestBody": {"required": True, "content": {"multipart/form-data": {"schema": {
    "type": "object", "required": ["type", "category", "text"], "additionalProperties": False,
    "properties": {"type": {"type": "string", "enum": [t.value for t in TicketType]},
                   "category": {"type": "string"}, "department": {"type": "string"},
                   "priority": {"type": "string", "enum": list(SLA_HOURS), "default": "Средний"},
                   "text": {"type": "string"}, "file": {"type": "string", "format": "binary"}}
}}}}}


async def parse_create(request: Request) -> tuple[TicketCreate, str | None]:
    if request.headers.get("content-type", "").split(";")[0] not in ("multipart/form-data", "application/x-www-form-urlencoded"):
        raise HTTPException(415, "Отправьте обращение как форму multipart/form-data")
    form = await request.form(max_files=1, max_fields=8, max_part_size=1024 * 1024)
    try:
        if len(form.multi_items()) != len(form):
            raise HTTPException(422, "Повторяющиеся поля формы запрещены")
        data = dict(form)
        attachment = data.pop("file", None)
        if attachment is not None and not isinstance(attachment, UploadFile) and attachment != "":
            raise HTTPException(422, "Поле file должно содержать файл")
        filename = None
        if isinstance(attachment, UploadFile) and attachment.filename:
            filename = attachment.filename.replace("\\", "/").rsplit("/", 1)[-1].strip()
            if not filename or filename in (".", "..") or len(filename) > 255 or any(ord(c) < 32 for c in filename):
                raise HTTPException(422, "Некорректное имя файла")
        try:
            return TicketCreate.model_validate(data), filename
        except ValidationError as error:
            detail = "; ".join(f"{'.'.join(map(str, item['loc']))}: {item['msg']}" for item in error.errors())
            raise HTTPException(422, detail) from error
    finally:
        await form.close()


def add_event(db: Session, ticket: Ticket, user: User, action: str, old: str | None, new: str | None):
    db.add(TicketEvent(ticket_id=ticket.id, actor_id=user.id, actor_name=user.display_name,
                       action=action, old_value=old, new_value=new))


def notify_processors(db: Session, ticket: Ticket):
    # Assignees are roles, not a real staff directory. Notify accessible reviewers.
    recipients = db.scalars(select(User).where(User.is_active.is_(True),
                           (User.role == "admin") | ((User.role == "manager") & (User.department == ticket.department))))
    for recipient in recipients:
        db.add(Notification(recipient_id=recipient.id, ticket_id=ticket.id, kind="assignment",
                            message=f"{ticket.code}: новое назначение. Ответственная роль — {ticket.assignee_role}."))


def notify_author(db: Session, ticket: Ticket, kind: str, message: str):
    if ticket.author_id is not None:
        db.add(Notification(recipient_id=ticket.author_id, ticket_id=ticket.id, kind=kind, message=message))


@app.post("/tickets", response_model=TicketOut, status_code=201, openapi_extra=CREATE_SCHEMA)
def create_ticket(db: DB, user: Writer, parsed: Annotated[tuple[TicketCreate, str | None], Depends(parse_create)]):
    data, filename = parsed
    if user.role != "admin" and data.department not in (None, user.department):
        raise HTTPException(403, "Вы можете создавать обращения только в своём подразделении")
    db.execute(sql_text("BEGIN IMMEDIATE"))
    rule = db.scalar(select(RoutingRule).where(RoutingRule.category == data.category))
    if rule is None:
        raise HTTPException(422, "Выберите категорию из предложенного списка")
    now = utcnow()
    ticket_id = (db.scalar(select(func.max(Ticket.id))) or 0) + 1
    ticket = Ticket(id=ticket_id, code=f"A-{ticket_id:03d}", type=data.type.value, category=data.category,
                    department=data.department if user.role == "admin" and data.department else user.department,
                    author_id=user.id, author_role=user.author_role, priority=data.priority, text=data.text,
                    status="Новое", assignee_role=rule.primary_assignee if rule.is_primary_available else rule.fallback_assignee,
                    fallback_assignee_role=rule.fallback_assignee, attachment_name=filename,
                    created_at=now, deadline_at=now + timedelta(hours=SLA_HOURS[data.priority]))
    db.add(ticket)
    db.flush()
    add_event(db, ticket, user, "created", None, ticket.code)
    notify_processors(db, ticket)
    db.commit()
    return ticket_out(ticket, user)


@app.get("/tickets/{ticket_id}", response_model=TicketOut)
def get_ticket(ticket_id: int, db: DB, user: CurrentUser):
    return ticket_out(require_ticket(db, user, ticket_id), user)


@app.patch("/tickets/{ticket_id}", response_model=TicketOut)
def update_ticket(ticket_id: int, data: TicketPatch, db: DB, user: Writer):
    require_manager(user)
    db.execute(sql_text("BEGIN IMMEDIATE"))
    ticket = require_ticket(db, user, ticket_id)
    updates = data.model_dump(exclude_unset=True, mode="json")
    if "final_resolution" in updates:
        updates["final_resolution"] = updates["final_resolution"] or None
    status = updates.get("status", ticket.status)
    if status != ticket.status and status not in TRANSITIONS.get(ticket.status, []):
        raise HTTPException(422, f"Переход «{ticket.status}» → «{status}» запрещён. Сначала верните завершённое обращение в работу.")
    resolution = updates.get("final_resolution", ticket.final_resolution)
    if status in FINAL_STATUSES and ("status" in updates or "final_resolution" in updates) and not (resolution or "").strip():
        raise HTTPException(422, "Укажите причину отказа" if status == "Отклонено" else "Укажите непустое итоговое решение")
    if ticket.status == "Новое" and status != "Новое" and ticket.first_response_at is None:
        ticket.first_response_at = utcnow()
    actions = {"status": "status_changed", "assignee_role": "assignee_changed", "final_resolution": "resolution_changed"}
    changed = set()
    for field, value in updates.items():
        old = getattr(ticket, field)
        if old != value:
            changed.add(field)
            add_event(db, ticket, user, actions[field], old, value)
            setattr(ticket, field, value)
    if "assignee_role" in changed:
        notify_processors(db, ticket)
    if "status" in changed and status == "Ожидает уточнения":
        notify_author(db, ticket, "clarification", f"{ticket.code}: нужно уточнение. Ответьте в комментариях к обращению.")
    if status in FINAL_STATUSES and changed.intersection({"status", "final_resolution"}):
        notify_author(db, ticket, "resolution", f"{ticket.code}: {status}. {ticket.final_resolution or ''}")
    db.commit()
    return ticket_out(ticket, user)


@app.post("/tickets/{ticket_id}/comments", response_model=CommentOut, status_code=201)
def add_comment(ticket_id: int, data: CommentCreate, db: DB, user: Writer):
    require_ticket(db, user, ticket_id)
    comment = Comment(ticket_id=ticket_id, author_id=user.id, author_role=user.author_role, text=data.text)
    db.add(comment)
    db.commit()
    return comment


@app.get("/tickets/{ticket_id}/comments", response_model=list[CommentOut])
def list_comments(ticket_id: int, db: DB, user: CurrentUser):
    require_ticket(db, user, ticket_id)
    return list(db.scalars(select(Comment).where(Comment.ticket_id == ticket_id).order_by(Comment.created_at, Comment.id)))


@app.get("/tickets/{ticket_id}/events", response_model=list[EventOut])
def list_events(ticket_id: int, db: DB, user: CurrentUser):
    require_ticket(db, user, ticket_id)
    return list(db.scalars(select(TicketEvent).where(TicketEvent.ticket_id == ticket_id).order_by(TicketEvent.created_at, TicketEvent.id)))


@app.get("/routing-rules", response_model=list[RoutingOut])
def list_rules(db: DB, user: CurrentUser):
    require_admin(user)
    return list(db.scalars(select(RoutingRule).order_by(RoutingRule.id)))


@app.patch("/routing-rules/{rule_id}", response_model=RoutingOut)
def update_rule(rule_id: int, data: RoutingPatch, db: DB, user: Writer):
    require_admin(user)
    db.execute(sql_text("BEGIN IMMEDIATE"))
    rule = db.get(RoutingRule, rule_id)
    if rule is None:
        raise HTTPException(404, "Правило не найдено")
    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(rule, field, value)
    db.commit()
    return rule


@app.get("/analytics")
def analytics(db: DB, user: CurrentUser, top_limit: Annotated[int, Query(ge=1, le=100)] = 5,
              scope: Literal["accessible", "mine"] = "accessible"):
    tickets = list(db.scalars(accessible_tickets(user, scope == "mine")))
    by_type = {kind.value: 0 for kind in TicketType}
    categories: dict[str, int] = {}
    hours = []
    completed = overdue = 0
    now = utcnow()
    for ticket in tickets:
        by_type[ticket.type] += 1
        categories[ticket.category] = categories.get(ticket.category, 0) + 1
        completed += ticket.status in COMPLETED
        overdue += ticket.status not in COMPLETED and ticket.deadline_at < now
        if ticket.first_response_at is not None:
            hours.append((ticket.first_response_at - ticket.created_at).total_seconds() / 3600)
    return {"total": len(tickets), "by_type": by_type, "completed_count": completed,
            "completed_percent": round(100 * completed / len(tickets), 2) if tickets else 0.0,
            "average_first_response_hours": round(sum(hours) / len(hours), 2) if hours else None,
            "first_response_sample_size": len(hours), "overdue_count": overdue,
            "top_categories": [{"category": category, "count": count} for category, count in
                               sorted(categories.items(), key=lambda item: (-item[1], item[0]))[:top_limit]]}


def accessible_notifications(user: User):
    visible_ids = accessible_tickets(user).with_only_columns(Ticket.id)
    return select(Notification).where(Notification.recipient_id == user.id, Notification.ticket_id.in_(visible_ids))


@app.get("/notifications")
def list_notifications(db: DB, user: CurrentUser, unread_only: bool = False):
    query = accessible_notifications(user)
    if unread_only:
        query = query.where(Notification.is_read.is_(False))
    notices = db.scalars(query.order_by(Notification.created_at.desc(), Notification.id.desc()).limit(100))
    return [{"id": n.id, "ticket_id": n.ticket_id, "kind": n.kind, "message": n.message,
             "is_read": n.is_read, "created_at": iso(n.created_at)} for n in notices]


@app.patch("/notifications/{notification_id}/read")
def read_notification(notification_id: int, db: DB, user: Writer):
    notice = db.scalar(accessible_notifications(user).where(Notification.id == notification_id))
    if notice is None:
        raise HTTPException(404, "Уведомление не найдено или недоступно")
    notice.is_read = True
    db.commit()
    return {"id": notice.id, "is_read": True}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=int(os.getenv("PORT", "8000")))
