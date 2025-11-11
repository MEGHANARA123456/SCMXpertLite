# mongoclient.py
from typing import Union, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Depends, Form
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, Field
from pymongo import MongoClient
from jose import jwt, JWTError
import hashlib
import re
import os
import logging
from datetime import datetime, timedelta

# ---------------------------
# Logging
# ---------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------
# Environment / JWT settings
# ---------------------------
# Optionally set these in your environment or .env
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-change-me")  # <- change in production
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# ---------------------------
# MongoDB Connect (env snippet)
# ---------------------------
MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB = os.getenv("MONGO_DB")

use_mongo = False
try:
    client = MongoClient(MONGO_URI)
    db = client[MONGO_DB]
    users_collection = db["users"]
    shipments_collection = db["shipments"]
    device_data_collection = db["device_data"]
    use_mongo = True
    logger.info("Connected to MongoDB: %s/%s", MONGO_URI, MONGO_DB)
except Exception as e:
    logger.warning("Mongo connection failed (falling back to in-memory): %s", e)
    # prepare in-memory fallback below

# ---------------------------
# In-memory fallback for users_collection
# ---------------------------
class InMemoryUsers:
    def __init__(self):
        self.users = []
        self._id_counter = 1

    def find_one(self, query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        # support {"$or": [{"username": ...}, {"email": ...}]} queries and exact dict queries
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
        class R: pass
        r = R()
        r.inserted_id = doc_copy["_id"]
        return r

if not use_mongo:
    users_collection = InMemoryUsers()
    shipments_collection = []  # simple list fallback for shipments
    device_data_collection = []  # simple list fallback for device data
    logger.info("Using in-memory fallback storage")

# ---------------------------
# Helpers
# ---------------------------
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def validate_email(email: str) -> bool:
    return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None

def validate_password(password: str) -> bool:
    return (
        len(password) >= 8
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"[0-9]", password)
        and re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    )

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ---------------------------
# FastAPI App
# ---------------------------
app = FastAPI(title="SCMXPertLite API", version="1.1")

# ---------------------------
# Pydantic models
# ---------------------------
class Signup(BaseModel):
    username: str
    email: EmailStr
    password: str
    confirm_password: str

class LoginPayload(BaseModel):
    username_or_email: str
    password: str

class Shipment(BaseModel):
    shipment_number: str
    container_number: str
    route_details: str
    goods_type: str
    expected_delivery_date: str
    po_number: str
    ndc_number: str
    serial_number_goods: str
    delivery_number: str
    batch_id: str
    shipment_description: str
    device: str

class DeviceData(BaseModel):
    device_id: str
    battery_level: str
    first_sensor_temperature: str
    route_from: str
    route_to: str
    timestamp: Optional[str] = Field(default_factory=lambda: datetime.utcnow().isoformat())

# ---------------------------
# Utility: get user from DB
# ---------------------------
def get_user_by_username_or_email(identifier: str) -> Optional[Dict[str, Any]]:
    identifier = identifier.strip().lower()
    # Normalize: match username stored as-is, email stored lowercased
    if use_mongo:
        user = users_collection.find_one({"$or": [{"username": identifier}, {"email": identifier}]})
    else:
        # In memory list: usernames stored as original; email lowercased
        user = users_collection.find_one({"$or": [{"username": identifier}, {"email": identifier}]})
    return user

# ---------------------------
# Dependency: verify token
# ---------------------------
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = get_user_by_username_or_email(username)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# ---------------------------
# Routes
# ---------------------------
@app.get("/")
def read_root():
    return {"message": "SCMXPertLite Backend Active", "using_mongo": use_mongo}

# ---------------------------
# Signup (form or json)
# ---------------------------
@app.post("/signup")
def signup(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...)
):
    username = username.strip()
    email_l = email.strip().lower()
    if not validate_email(email_l):
        raise HTTPException(status_code=400, detail="Invalid email format")
    if username == "":
        raise HTTPException(status_code=400, detail="Username required")
    if not validate_password(password):
        raise HTTPException(
            status_code=400,
            detail="Weak password. Requirements: >=8 chars, uppercase, lowercase, number, special char."
        )
    if password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    # check existing
    if get_user_by_username_or_email(username) or get_user_by_username_or_email(email_l):
        raise HTTPException(status_code=400, detail="Username or email already exists")

    hashed = hash_password(password)
    user_doc = {"username": username, "email": email_l, "password": hashed}
    if use_mongo:
        res = users_collection.insert_one(user_doc)
        inserted_id = getattr(res, "inserted_id", None)
        logger.info("Inserted user id=%s", inserted_id)
    else:
        res = users_collection.insert_one(user_doc)
        logger.info("Inserted user into in-memory storage")

    return {"message": f"User {username} signed up successfully"}

# ---------------------------
# Login (token endpoint) - works with OAuth2PasswordRequestForm (Swagger friendly)
# ---------------------------
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    identifier = form_data.username.strip()
    password = form_data.password

    user = get_user_by_username_or_email(identifier)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    stored_hash = user.get("password")
    if stored_hash != hash_password(password):
        raise HTTPException(status_code=401, detail="Invalid password")

    # subject will be username (so tokens can be looked up by username)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# ---------------------------
# Protected: create shipment
# ---------------------------
@app.post("/create-shipment")
def create_shipment(
    shipment_number: str = Form(...),
    container_number: str = Form(...),
    route_details: str = Form(...),
    goods_type: str = Form(...),
    expected_delivery_date: str = Form(...),
    po_number: str = Form(...),
    ndc_number: str = Form(...),
    serial_number_goods: str = Form(...),
    delivery_number: str = Form(...),
    batch_id: str = Form(...),
    shipment_description: str = Form(...),
    device: str = Form(...),
    current_user: dict = Depends(get_current_user)  # <-- protected
):
    # Prevent duplicate shipment
    if use_mongo:
        if shipments_collection.find_one({"shipment_number": shipment_number}):
            raise HTTPException(status_code=400, detail="Shipment number already exists")
        doc = {
            "shipment_number": shipment_number,
            "container_number": container_number,
            "route_details": route_details,
            "goods_type": goods_type,
            "expected_delivery_date": expected_delivery_date,
            "po_number": po_number,
            "ndc_number": ndc_number,
            "serial_number_goods": serial_number_goods,
            "delivery_number": delivery_number,
            "batch_id": batch_id,
            "shipment_description": shipment_description,
            "device": device,
            "created_by": current_user.get("username"),
            "created_at": datetime.utcnow()
        }
        shipments_collection.insert_one(doc)
    else:
        doc = {
            "shipment_number": shipment_number,
            "container_number": container_number,
            "route_details": route_details,
            "goods_type": goods_type,
            "expected_delivery_date": expected_delivery_date,
            "po_number": po_number,
            "ndc_number": ndc_number,
            "serial_number_goods": serial_number_goods,
            "delivery_number": delivery_number,
            "batch_id": batch_id,
            "shipment_description": shipment_description,
            "device": device,
            "created_by": current_user.get("username"),
            "created_at": datetime.utcnow().isoformat()
        }
        shipments_collection.append(doc)

    return {"message": "Shipment created successfully", "shipment_number": shipment_number}

# ---------------------------
# Protected: add device data
# ---------------------------
@app.post("/device-data")
def add_device_data(
    device_id: str = Form(...),
    battery_level: str = Form(...),
    first_sensor_temperature: str = Form(...),
    route_from: str = Form(...),
    route_to: str = Form(...),
    timestamp: str = Form(default_factory=lambda: datetime.utcnow().isoformat()),
    current_user: dict = Depends(get_current_user)
):
    doc = {
        "device_id": device_id,
        "battery_level": battery_level,
        "first_sensor_temperature": first_sensor_temperature,
        "route_from": route_from,
        "route_to": route_to,
        "timestamp": timestamp,
        "created_by": current_user.get("username"),
        "created_at": datetime.utcnow()
    }
    if use_mongo:
        device_data_collection.insert_one(doc)
    else:
        device_data_collection.append(doc)

    return {"message": f"Device data stored for {device_id}"}

# ---------------------------
# Public reads (no auth)
# ---------------------------
@app.get("/shipments")
def get_shipments():
    if use_mongo:
        shipments = list(shipments_collection.find({}, {"_id": 0}))
    else:
        shipments = shipments_collection
    return {"total_shipments": len(shipments), "shipments": shipments}

@app.get("/device-data/{device_id}")
def get_device_data(device_id: str):
    if use_mongo:
        data = list(device_data_collection.find({"device_id": device_id}, {"_id": 0}))
    else:
        data = [d for d in device_data_collection if d.get("device_id") == device_id]
    if not data:
        raise HTTPException(status_code=404, detail="No data found for this device")
    return {"device_id": device_id, "records": data}

# ---------------------------
# Keep your item CRUD routes
# ---------------------------
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
