"""
Database Schemas

Pydantic models defining MongoDB collections. Class name lowercased is the collection name.
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import datetime

# User accounts
class User(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    email: EmailStr
    password_hash: str = Field(..., description="BCrypt hashed password")
    display_name: Optional[str] = None
    avatar_url: Optional[str] = None
    role: Literal["user","admin"] = "user"
    is_active: bool = True

class Profile(BaseModel):
    user_id: str
    bio: Optional[str] = None
    interests: List[str] = []
    theme: Literal["electric","neon","gold","midnight"] = "electric"
    social: dict = {}

# Media assets (images, videos, 3D models)
class Media(BaseModel):
    user_id: str
    title: str
    description: Optional[str] = None
    kind: Literal["image","video","model","clip"]
    file_id: Optional[str] = None  # GridFS id as string
    mime_type: Optional[str] = None
    tags: List[str] = []
    visibility: Literal["public","private"] = "public"

class Post(BaseModel):
    user_id: str
    content: str
    media_ids: List[str] = []

class Message(BaseModel):
    room: str = "global"
    user_id: str
    text: str

class ContactSubmission(BaseModel):
    name: str
    email: EmailStr
    message: str

# Utility for timestamps included by database helper on insert
class Timestamped(BaseModel):
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
