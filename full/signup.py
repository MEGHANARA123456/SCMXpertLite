from typing import Union
from fastapi import FastAPI, Form, HTTPException
from pydantic import BaseModel, EmailStr, validator
import re

app = FastAPI(title="FastAPI Signup + Login Validation ")


# Simple In-memory "Database"

users_db = {}


# Root Route

@app.get("/")
def read_root():
    return {"Hello": "World"}


# Password Validation Function

def validate_password_strength(password: str):
    """
    Validates if password meets all conditions:
    - Minimum 8 characters
    - Contains uppercase, lowercase, number, and special character
    """
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

# Signup Route with All Conditions

@app.post("/signup")
def signup(
    username: str = Form(...),
    email: EmailStr = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...)
):
    # 1️ Check if username already exists
    if username in users_db:
        raise HTTPException(status_code=400, detail="Username already exists")

    # 2️ Password strength validation
    if not validate_password_strength(password):
        raise HTTPException(
            status_code=400,
            detail=(
                "Password must be at least 8 characters long, "
                "and include an uppercase, lowercase, number, and special character."
            ),
        )

    # 3️ Confirm password match
    if password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    # 4️ If all good → Save user
    users_db[username] = {"email": email, "password": password}
    return {"message": f"Signup successful! Welcome, {username}"}
# Login Route (Unchanged)

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    print(username, password)  # original line

    user = users_db.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid password")

    return {"message": f"Welcome back, {username}!"}


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

# getting error




from typing import Union
from fastapi import FastAPI, HTTPException, Form
from pydantic import BaseModel, EmailStr
from pymongo import MongoClient
from datetime import datetime
import hashlib, re, os, logging

# ------------------------------------------------------------
# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ------------------------------------------------------------
# MongoDB Connection
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "me")

try:
    client = MongoClient(MONGO_URI)
    db = client[MONGO_DB]
    users_collection = db["users"]
    shipments_collection = db["shipments"]
    device_data_collection = db["device_data"]
    use_mongo = True
    logger.info("Connected to MongoDB")
except Exception as e:
    logger.warning("Mongo connection failed: %s", e)
    use_mongo = False

# ------------------------------------------------------------
# Helper Functions
def hash_password(password: str): return hashlib.sha256(password.encode()).hexdigest()

def validate_email(email: str): return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def validate_password(password: str):
    return (
        len(password) >= 8
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"[0-9]", password)
        and re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    )

# ------------------------------------------------------------
# FastAPI App
app = FastAPI(title="SCMXPertLite Backend (Form Version)", version="2.0")

# ------------------------------------------------------------
@app.get("/")
def root():
    return {"message": "Backend Active", "using_mongo": use_mongo}

# ------------------------------------------------------------
# 🧍 SIGNUP (Form-based)
# ------------------------------------------------------------
@app.post("/signup")
def signup(
    username: str = Form(...),
    email: EmailStr = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...)
):
    if not validate_email(email):
        raise HTTPException(status_code=400, detail="Invalid email format")

    if not validate_password(password):
        raise HTTPException(
            status_code=400,
            detail="Weak password. Must include uppercase, lowercase, number, and special char."
        )

    if password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    if users_collection.find_one({"$or": [{"username": username}, {"email": email}]}):
        raise HTTPException(status_code=400, detail="Username or Email already exists")

    hashed_pw = hash_password(password)
    users_collection.insert_one({"username": username, "email": email, "password": hashed_pw})
    return {"message": f"User {username} signed up successfully"}

# ------------------------------------------------------------
#  LOGIN (Form-based)
# ------------------------------------------------------------
@app.post("/login")
def login(username_or_email: str = Form(...), password: str = Form(...)):
    user = users_collection.find_one({"$or": [{"username": username_or_email}, {"email": username_or_email}]})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user["password"] != hash_password(password):
        raise HTTPException(status_code=401, detail="Invalid password")

    return {"message": f"Welcome back, {user['username']}!"}

# ------------------------------------------------------------
# CREATE SHIPMENT (Form-based)
# ------------------------------------------------------------
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
    device: str = Form(...)
):
    if shipments_collection.find_one({"shipment_number": shipment_number}):
        raise HTTPException(status_code=400, detail="Shipment already exists")

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
        "created_at": datetime.utcnow()
    }
    shipments_collection.insert_one(doc)
    return {"message": f"Shipment {shipment_number} created successfully"}

# ------------------------------------------------------------
#  GET ALL SHIPMENTS
# ------------------------------------------------------------
@app.get("/shipments")
def get_shipments():
    shipments = list(shipments_collection.find({}, {"_id": 0}))
    return {"total_shipments": len(shipments), "shipments": shipments}

# ------------------------------------------------------------
#  DEVICE DATA STREAM (Form-based)
# ------------------------------------------------------------
@app.post("/device-data")
def add_device_data(
    device_id: str = Form(...),
    battery_level: str = Form(...),
    first_sensor_temperature: str = Form(...),
    route_from: str = Form(...),
    route_to: str = Form(...),
    timestamp: str = Form(datetime.utcnow().isoformat())
):
    data_doc = {
        "device_id": device_id,
        "battery_level": battery_level,
        "first_sensor_temperature": first_sensor_temperature,
        "route_from": route_from,
        "route_to": route_to,
        "timestamp": timestamp,
        "created_at": datetime.utcnow()
    }
    device_data_collection.insert_one(data_doc)
    return {"message": f"Device data stored successfully for Device ID {device_id}"}

# ------------------------------------------------------------
#  GET DEVICE DATA BY DEVICE ID
# ------------------------------------------------------------
@app.get("/device-data/{device_id}")
def get_device_data(device_id: str):
    data = list(device_data_collection.find({"device_id": device_id}, {"_id": 0}))
    if not data:
        raise HTTPException(status_code=404, detail="No data found for this device")
    return {"device_id": device_id, "records": data}

# ------------------------------------------------------------
# CRUD Item Routes (for compatibility)
# ------------------------------------------------------------
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
#working code in ship,device,log,sign