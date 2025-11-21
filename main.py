import os
import io
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Header, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, EmailStr
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Profile as ProfileSchema, Media as MediaSchema, Post as PostSchema, Message as MessageSchema, ContactSubmission

# Password hashing
try:
    import bcrypt
except Exception:  # pragma: no cover
    bcrypt = None

app = FastAPI(title="Neon Nexus API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Helpers ---
class AuthUser(BaseModel):
    id: str
    username: str
    email: EmailStr
    role: str = "user"


def hash_password(password: str) -> str:
    if not bcrypt:
        raise HTTPException(status_code=500, detail="Security module unavailable")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()


def verify_password(password: str, hashed: str) -> bool:
    if not bcrypt:
        return False
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def get_collection(name: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    return db[name]


def create_session(user_id: str, ttl_minutes: int = 60*24) -> str:
    token = secrets.token_urlsafe(32)
    sessions = get_collection("session")
    sessions.insert_one({
        "token": token,
        "user_id": user_id,
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)
    })
    return token


def get_user_from_token(authorization: Optional[str]) -> Optional[AuthUser]:
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        token = parts[1]
    else:
        token = authorization
    sessions = get_collection("session")
    sess = sessions.find_one({"token": token})
    if not sess:
        return None
    if sess.get("expires_at") and sess["expires_at"] < datetime.now(timezone.utc):
        sessions.delete_one({"_id": sess["_id"]})
        return None
    users = get_collection("user")
    u = users.find_one({"_id": ObjectId(sess["user_id"])}) if ObjectId.is_valid(sess["user_id"]) else users.find_one({"_id": sess["user_id"]})
    if not u:
        return None
    return AuthUser(id=str(u["_id"]), username=u.get("username"), email=u.get("email"), role=u.get("role","user"))


async def get_current_user(authorization: Optional[str] = Header(None)) -> AuthUser:
    user = get_user_from_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user


# --- Routes ---
@app.get("/")
def root():
    return {"service": "Neon Nexus API", "status": "ok"}


class RegisterBody(BaseModel):
    username: str
    email: EmailStr
    password: str


@app.post("/auth/register")
def register(body: RegisterBody):
    users = get_collection("user")
    if users.find_one({"$or": [{"email": body.email}, {"username": body.username}] }):
        raise HTTPException(status_code=409, detail="User already exists")
    user_doc = {
        "username": body.username,
        "email": body.email,
        "password_hash": hash_password(body.password),
        "role": "user",
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = users.insert_one(user_doc)
    profiles = get_collection("profile")
    profiles.insert_one({"user_id": str(res.inserted_id), "theme": "electric", "interests": []})
    token = create_session(str(res.inserted_id))
    return {"token": token, "user": {"id": str(res.inserted_id), "username": body.username, "email": body.email}}


class LoginBody(BaseModel):
    email_or_username: str
    password: str


@app.post("/auth/login")
def login(body: LoginBody):
    users = get_collection("user")
    u = users.find_one({"$or": [{"email": body.email_or_username}, {"username": body.email_or_username}]})
    if not u or not verify_password(body.password, u.get("password_hash","")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_session(str(u["_id"]))
    return {"token": token, "user": {"id": str(u["_id"]), "username": u.get("username"), "email": u.get("email"), "role": u.get("role","user")}}


@app.get("/me")
async def me(current: AuthUser = Depends(get_current_user)):
    profiles = get_collection("profile")
    prof = profiles.find_one({"user_id": current.id}) or {}
    prof["id"] = str(prof.get("_id")) if prof.get("_id") else None
    prof.pop("_id", None)
    return {"user": current.model_dump(), "profile": prof}


class UpdateProfileBody(BaseModel):
    display_name: Optional[str] = None
    bio: Optional[str] = None
    theme: Optional[str] = None


@app.post("/profile")
async def update_profile(body: UpdateProfileBody, current: AuthUser = Depends(get_current_user)):
    profiles = get_collection("profile")
    profiles.update_one({"user_id": current.id}, {"$set": {k:v for k,v in body.model_dump(exclude_none=True).items()}}, upsert=True)
    return {"ok": True}


# --- Media Uploads (GridFS) ---
try:
    from gridfs import GridFS
    fs = GridFS(db) if db is not None else None
except Exception:
    fs = None


@app.post("/media/upload")
async def upload_media(
    title: str = Form(...),
    kind: str = Form(...),  # image, video, model, clip
    description: Optional[str] = Form(None),
    tags: Optional[str] = Form(None),  # comma-separated
    visibility: str = Form("public"),
    file: UploadFile = File(...),
    current: AuthUser = Depends(get_current_user)
):
    if fs is None:
        raise HTTPException(status_code=500, detail="Storage not available")
    raw = await file.read()
    # rudimentary anti-lag: cap single upload to 200MB
    if len(raw) > 200 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large")
    file_id = fs.put(raw, filename=file.filename, content_type=file.content_type, uploader=current.id)
    media = get_collection("media")
    doc = {
        "user_id": current.id,
        "title": title,
        "description": description,
        "kind": kind,
        "file_id": str(file_id),
        "mime_type": file.content_type,
        "tags": [t.strip() for t in (tags.split(",") if tags else []) if t.strip()],
        "visibility": visibility,
        "optimized": True,  # placeholder flag after upload
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }
    res = media.insert_one(doc)
    return {"id": str(res.inserted_id), "file_id": str(file_id)}


@app.get("/media")
async def list_media(kind: Optional[str] = None, user_id: Optional[str] = None, limit: int = 30):
    media = get_collection("media")
    query = {}
    if kind:
        query["kind"] = kind
    if user_id:
        query["user_id"] = user_id
    items = list(media.find(query).sort("created_at", -1).limit(min(limit, 100)))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return {"items": items}


@app.get("/media/file/{file_id}")
async def serve_file(file_id: str):
    if fs is None:
        raise HTTPException(status_code=404, detail="File not found")
    try:
        gridout = fs.get(ObjectId(file_id))
    except Exception:
        raise HTTPException(status_code=404, detail="File not found")
    headers = {"Content-Disposition": f"inline; filename={gridout.filename}"}
    return StreamingResponse(io.BytesIO(gridout.read()), media_type=gridout.content_type, headers=headers)


# --- Posts / Social Feed ---
class CreatePostBody(BaseModel):
    content: str
    media_ids: List[str] = []


@app.post("/posts")
async def create_post(body: CreatePostBody, current: AuthUser = Depends(get_current_user)):
    posts = get_collection("post")
    doc = {
        "user_id": current.id,
        "content": body.content,
        "media_ids": body.media_ids,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }
    res = posts.insert_one(doc)
    return {"id": str(res.inserted_id)}


@app.get("/feed")
async def feed(limit: int = 50):
    posts = get_collection("post")
    items = list(posts.find({}).sort("created_at", -1).limit(min(limit, 100)))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return {"items": items}


# --- Contact ---
class ContactBody(BaseModel):
    name: str
    email: EmailStr
    message: str


@app.post("/contact")
async def submit_contact(body: ContactBody):
    create_document("contactsubmission", body.model_dump())
    return {"ok": True}


# --- Admin ---
@app.get("/admin/overview")
async def admin_overview(current: AuthUser = Depends(get_current_user)):
    if current.role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    stats = {
        "users": get_collection("user").count_documents({}),
        "media": get_collection("media").count_documents({}),
        "posts": get_collection("post").count_documents({}),
        "messages": get_collection("message").count_documents({}),
    }
    return stats


# --- WebSocket Chat ---
class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active:
            self.active.remove(websocket)

    async def broadcast(self, data: dict):
        for ws in list(self.active):
            try:
                await ws.send_json(data)
            except Exception:
                self.disconnect(ws)


manager = ConnectionManager()


@app.websocket("/ws/chat")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            payload = await websocket.receive_json()
            payload["timestamp"] = datetime.now(timezone.utc).isoformat()
            # persist message
            try:
                get_collection("message").insert_one({
                    "room": payload.get("room","global"),
                    "user": payload.get("user","anon"),
                    "text": payload.get("text",""),
                    "created_at": datetime.now(timezone.utc)
                })
            except Exception:
                pass
            await manager.broadcast(payload)
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:50]}"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
