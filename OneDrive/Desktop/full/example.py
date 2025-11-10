from typing import Union
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse  #pipinstall fastapi,uvicorn
from pymongo import MongoClient   #pipinstall pymongo
from dotenv import load_dotenv
import os

#  Load Environment Variables

load_dotenv()

#  Get MongoDB credentials from .env (or use defaults)

# Get environment variables
MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB = os.getenv("MONGO_DB")       # your database name

#  Connect to MongoDB
client = MongoClient(MONGO_URI)
db = client[MONGO_DB]

#  Access the "users" collection
users_collection = db["users"]

# Initialize FastAPI
app = FastAPI(title="FastAPI MongoDB Demo")

#  Root Route - Check Connection
@app.get("/")
def read_root():
    return {"message": f"Connected successfully to MongoDB database '{MONGO_DB}'"}


@app.get("/hi")
def say_hello():
    return {"Hello": "hi", "database": MONGO_DB}

@app.get("/login")
def login(email: str, password: str):
    #  Validate email format
    if "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email format")

    #  Check if user exists in DB
    user = users_collection.find_one({"email": email, "password": password})
    if not user:
        raise HTTPException(status_code=404, detail="User not found or wrong password")

    return {"message": f"Welcome, {email}!"}

@app.post("/add_user")
def add_user(name: str, email: str, password: str):
    # Email validation
    if "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email address")

    #  Check if user already exists
    if users_collection.find_one({"email": email}):
        raise HTTPException(status_code=400, detail="Email already registered")

    #  Insert into MongoDB
    user = {"name": name, "email": email, "password": password}
    users_collection.insert_one(user)

    return {"message": "User added successfully", "user": {"name": name, "email": email}}

@app.get("/test_db")
def test_db():
    collections = db.list_collection_names()
    return {"connected_to": MONGO_DB, "collections": collections}

