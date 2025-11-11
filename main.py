# mongoclient.py
"""
FastAPI app using the exact environment-variable Mongo connection snippet you provided:
MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB = os.getenv("MONGO_DB")
client = MongoClient(MONGO_URI)
db = client[MONGO_DB]
users_collection = db["users"]
If Mongo isn't reachable, falls back to in-memory.
"""
from typing import Union
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pymongo import MongoClient
import hashlib
import re
import os
import logging
from typing import Optional, Dict, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ------------------------------------------------------------
# Use your exact environment snippet
# ------------------------------------------------------------
# Get environment variables
MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB = os.getenv("MONGO_DB")       # your database name

#  Connect to MongoDB
# (we call exactly what you asked for; we will wrap in try/except below)
try:
    client = MongoClient(MONGO_URI)
    db = client[MONGO_DB]
    users_collection = db["users"]
    use_mongo = True
    logger.info("Mongo variables: MONGO_URI=%s MONGO_DB=%s", MONGO_URI, MONGO_DB)
except Exception as e:
    # If anything fails (None values or connection), fall back to in-memory
    logger.warning("Mongo connection using env vars failed: %s", e)
    use_mongo = False
    client = None
    db = None
    users_collection = None

# ------------------------------------------------------------
# In-memory fallback (if Mongo not usable)
# ------------------------------------------------------------
class InMemoryUsers:
    def _init_(self):
        self.users = []
        self._id_counter = 1

    def find_one(self, query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if "$or" in query:
            for clause in query["$or"]:
                for k, v in clause.items():
                    for u in self.users:
                        if u.get(k) == v:
                            return u
            return None
        for u in self.users:
            if all(u.get(k) == v for k, v in query.items()):
                return u
        return None

    def insert_one(self, doc: Dict[str, Any]):
        doc_copy = doc.copy()
        doc_copy["_id"] = self._id_counter
        self._id_counter += 1
        self.users.append(doc_copy)
        class R:
            def _init_(self, inserted_id): self.inserted_id = inserted_id
        return R(doc_copy["_id"])

if not use_mongo:
    users_collection = InMemoryUsers()
    logger.info("Using in-memory users_collection fallback")

# ------------------------------------------------------------
# Exact helper functions you provided
# ------------------------------------------------------------
def hash_password(password: str):
    return hashlib.sha256(password.encode()).hexdigest()

def validate_email(email: str):
    # original returned a match; return boolean for clarity
    return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None

def validate_password(password: str):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"[0-9]", password) and
        re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    )

# FastAPI app & models

app = FastAPI(title="FastAPI MongoDB Demo (env-snippet)", version="1.0")

class Signup(BaseModel):
    username: str
    email: str
    password: str
    confirm_password: str

class Login(BaseModel):
    username_or_email: str
    password: str

# Simple root route as requested

@app.get("/")
def read_root():
    return {"Hello": "World"}

# Status route to inspect Mongo usage

@app.get("/status")
def status():
    return {
        "using_mongo": use_mongo,
        "MONGO_URI": MONGO_URI,
        "MONGO_DB": MONGO_DB
    }

# ------------------------------------------------------------
# Signup route using your exact helpers
# ------------------------------------------------------------
@app.post("/signup")
def signup(payload: Signup):
    username = payload.username.strip()
    email = payload.email.strip().lower()
    password = payload.password
    confirm_password = payload.confirm_password

    if not validate_email(email):
        raise HTTPException(status_code=400, detail="Invalid email format")

    # check for existing user
    existing = users_collection.find_one({"$or": [{"username": username}, {"email": email}]})
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already exists")

    if not validate_password(password):
        raise HTTPException(
            status_code=400,
            detail="Weak password. Requirements: >=8 chars, uppercase, lowercase, number, special char."
        )

    if password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    hashed_pw = hash_password(password)
    user_doc = {"username": username, "email": email, "password": hashed_pw}

    try:
        result = users_collection.insert_one(user_doc)
        inserted_id = getattr(result, "inserted_id", None)
        logger.info("Inserted user %s id=%s using_mongo=%s", username, inserted_id, use_mongo)
    except Exception as e:
        logger.exception("Failed to insert user: %s", e)
        raise HTTPException(status_code=500, detail=f"Insert failed: {e}")

    return {
        "message": "Signup successful",
        "inserted_id": str(inserted_id),
        "user": {"_id": str(inserted_id), "username": username, "email": email},
        "using_mongo": use_mongo
    }

# ------------------------------------------------------------
# Login route
# ------------------------------------------------------------
@app.post("/login")
def login(payload: Login):
    identifier = payload.username_or_email.strip()
    password = payload.password

    user = users_collection.find_one({"$or": [{"username": identifier}, {"email": identifier}]})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    stored_hash = user.get("password")
    if not stored_hash or hash_password(password) != stored_hash:
        raise HTTPException(status_code=401, detail="Invalid password")

    return {"message": "Login successful", "username": user.get("username"), "email": user.get("email")}

# ------------------------------------------------------------
# Optional debug route to inspect in-memory users (only when not using mongo)
# ------------------------------------------------------------
@app.get("/_debug_inmemory_users")
def debug_inmemory_users():
    if use_mongo:
        raise HTTPException(status_code=400, detail="Available only in in-memory mode")
    return {"users": users_collection.users}
# Example Item Model for CRUD routes

class Item(BaseModel):
    name: str
    price: float
    is_offer: Union[bool, None] = None

@app.put("/items/{item_id}")
def update_item(item_id: int, item: Item):
    return {"item_name": item.name, "item_id": item_id}

@app.patch("/items/{item_id}")
def patch_item(item_id: int, item: dict):
    return {"message": f"Item {item_id} partially updated", "item": item}

@app.delete("/items/{item_id}")
def delete_item(item_id: int):
    return {"message": f"Item {item_id} deleted"}
