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
