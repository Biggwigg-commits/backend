from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Union
import uuid
from datetime import datetime, timedelta
import hashlib
import jwt
from passlib.context import CryptContext
import stripe
import re
import base64
import random

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Stripe configuration
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY', 'sk_test_dummy_key')

# JWT configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Create the main app without a prefix
app = FastAPI(title="PayMe API", version="2.0")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Utility Functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_jwt_token(user_id: str) -> str:
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload["user_id"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    user_id = verify_jwt_token(token)
    user = await db.users.find_one({"user_id": user_id})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return User(**user)

def validate_phone(phone: str) -> bool:
    # Simple phone validation - accept various formats
    cleaned_phone = re.sub(r'[^\d]', '', phone)
    return len(cleaned_phone) >= 10 and len(cleaned_phone) <= 15

def generate_card_number() -> str:
    # Generate a valid-looking card number (not real)
    return f"4{random.randint(100, 999)} {random.randint(1000, 9999)} {random.randint(1000, 9999)} {random.randint(1000, 9999)}"

def generate_cvv() -> str:
    return f"{random.randint(100, 999)}"

def generate_expiry() -> str:
    # Generate expiry 3-5 years from now
    current_year = datetime.now().year % 100
    expiry_year = (current_year + random.randint(3, 5)) % 100
    expiry_month = random.randint(1, 12)
    return f"{expiry_month:02d}/{expiry_year:02d}"

# Pydantic Models
class User(BaseModel):
    user_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    email: EmailStr
    phone: str
    password_hash: str
    balance: float = 0.0
    profile_picture: Optional[str] = None  # Base64 encoded image
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_verified: bool = False
    
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    phone: str
    password: str

class UserLogin(BaseModel):
    identifier: str  # Can be email or phone
    password: str

class ProfilePictureUpdate(BaseModel):
    profile_picture: str  # Base64 encoded image

class VirtualCard(BaseModel):
    card_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    card_number: str
    card_holder_name: str
    cvv: str
    expiry_date: str
    is_locked: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    monthly_spend: float = 0.0
    
class CardSpendUpdate(BaseModel):
    amount: float
    merchant: str
    description: Optional[str] = None

class Transaction(BaseModel):
    transaction_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sender_id: str
    recipient_id: Optional[str] = None
    recipient_identifier: Optional[str] = None  # Email or phone for external sends
    amount: float
    fee: float = 0.0
    transaction_type: str  # 'send', 'receive', 'add_funds', 'withdraw', 'request', 'card_purchase'
    status: str = 'pending'  # 'pending', 'completed', 'failed', 'cancelled'
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    stripe_payment_intent_id: Optional[str] = None
    card_id: Optional[str] = None  # For card transactions

class MoneyRequest(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    requester_id: str
    requestee_id: Optional[str] = None
    requestee_identifier: str  # Email, phone, or username
    amount: float
    description: Optional[str] = None
    status: str = 'pending'  # 'pending', 'paid', 'declined', 'cancelled'
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime = Field(default_factory=lambda: datetime.utcnow() + timedelta(days=30))

class SendMoneyRequest(BaseModel):
    recipient_identifier: str  # Email, phone, or username
    amount: float
    description: Optional[str] = None

class RequestMoneyRequest(BaseModel):
    requestee_identifier: str  # Email, phone, or username
    amount: float
    description: Optional[str] = None

class AddFundsRequest(BaseModel):
    amount: float
    payment_method_id: str  # Stripe payment method ID

class ConnectedAccount(BaseModel):
    account_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    account_type: str  # 'bank_account', 'debit_card'
    account_name: str  # User-friendly name
    last_four: str
    is_default: bool = False
    stripe_account_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class WithdrawRequest(BaseModel):
    amount: float
    account_id: str
    transfer_speed: str = 'standard'  # 'standard' or 'instant'

class ConnectAccountRequest(BaseModel):
    account_type: str  # 'bank_account', 'debit_card'
    account_name: str
    stripe_token: str  # Stripe token for the account

class PayRequestRequest(BaseModel):
    request_id: str

class CardPurchaseRequest(BaseModel):
    amount: float
    merchant: str
    description: Optional[str] = None

# API Routes

@api_router.get("/")
async def root():
    return {"message": "PayMe API v2.0 - Your Digital Wallet"}

# Authentication Routes
@api_router.post("/auth/register")
async def register_user(user_data: UserCreate):
    # Check if user already exists
    existing_user = await db.users.find_one({
        "$or": [
            {"email": user_data.email},
            {"phone": user_data.phone},
            {"username": user_data.username}
        ]
    })
    
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Validate phone number
    if not validate_phone(user_data.phone):
        raise HTTPException(status_code=400, detail="Invalid phone number")
    
    # Create user
    user = User(
        username=user_data.username,
        email=user_data.email,
        phone=user_data.phone,
        password_hash=hash_password(user_data.password)
    )
    
    await db.users.insert_one(user.dict())
    
    # Create virtual card for the user
    virtual_card = VirtualCard(
        user_id=user.user_id,
        card_number=generate_card_number(),
        card_holder_name=user_data.username.upper(),
        cvv=generate_cvv(),
        expiry_date=generate_expiry()
    )
    
    await db.virtual_cards.insert_one(virtual_card.dict())
    
    # Create JWT token
    token = create_jwt_token(user.user_id)
    
    return {
        "message": "User registered successfully",
        "token": token,
        "user": {
            "user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "phone": user.phone,
            "balance": user.balance,
            "profile_picture": user.profile_picture
        }
    }

@api_router.post("/auth/login")
async def login_user(login_data: UserLogin):
    # Find user by email, phone, or username
    user = await db.users.find_one({
        "$or": [
            {"email": login_data.identifier},
            {"phone": login_data.identifier},
            {"username": login_data.identifier}
        ]
    })
    
    if not user or not verify_password(login_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create JWT token
    token = create_jwt_token(user["user_id"])
    
    return {
        "message": "Login successful",
        "token": token,
        "user": {
            "user_id": user["user_id"],
            "username": user["username"],
            "email": user["email"],
            "phone": user["phone"],
            "balance": user["balance"],
            "profile_picture": user.get("profile_picture")
        }
    }

# User Profile Routes
@api_router.get("/user/profile")
async def get_user_profile(current_user: User = Depends(get_current_user)):
    return {
        "user_id": current_user.user_id,
        "username": current_user.username,
        "email": current_user.email,
        "phone": current_user.phone,
        "balance": current_user.balance,
        "profile_picture": current_user.profile_picture,
        "created_at": current_user.created_at
    }

@api_router.post("/user/profile-picture")
async def update_profile_picture(picture_data: ProfilePictureUpdate, current_user: User = Depends(get_current_user)):
    # Update user's profile picture
    result = await db.users.update_one(
        {"user_id": current_user.user_id},
        {"$set": {"profile_picture": picture_data.profile_picture}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=400, detail="Failed to update profile picture")
    
    return {"message": "Profile picture updated successfully"}

@api_router.get("/user/search")
async def search_users(query: str, current_user: User = Depends(get_current_user)):
    # Search users by username, email, or phone (exclude current user)
    users = await db.users.find({
        "$and": [
            {"user_id": {"$ne": current_user.user_id}},
            {
                "$or": [
                    {"username": {"$regex": query, "$options": "i"}},
                    {"email": {"$regex": query, "$options": "i"}},
                    {"phone": {"$regex": query, "$options": "i"}}
                ]
            }
        ]
    }).limit(10).to_list(10)
    
    return [{
        "user_id": user["user_id"],
        "username": user["username"],
        "email": user["email"][:3] + "***@" + user["email"].split("@")[1],  # Partially hide email
        "phone": user["phone"][:3] + "***" + user["phone"][-4:],  # Partially hide phone
        "profile_picture": user.get("profile_picture")
    } for user in users]

# Virtual Card Routes
@api_router.get("/card")
async def get_virtual_card(current_user: User = Depends(get_current_user)):
    card = await db.virtual_cards.find_one({"user_id": current_user.user_id})
    
    if not card:
        # Create card if it doesn't exist
        virtual_card = VirtualCard(
            user_id=current_user.user_id,
            card_number=generate_card_number(),
            card_holder_name=current_user.username.upper(),
            cvv=generate_cvv(),
            expiry_date=generate_expiry()
        )
        
        await db.virtual_cards.insert_one(virtual_card.dict())
        card = virtual_card.dict()
    
    return {
        "card_id": card["card_id"],
        "card_number": card["card_number"],
        "card_holder_name": card["card_holder_name"],
        "cvv": card["cvv"],
        "expiry_date": card["expiry_date"],
        "is_locked": card["is_locked"],
        "monthly_spend": card.get("monthly_spend", 0.0)
    }

@api_router.post("/card/lock")
async def toggle_card_lock(current_user: User = Depends(get_current_user)):
    card = await db.virtual_cards.find_one({"user_id": current_user.user_id})
    
    if not card:
        raise HTTPException(status_code=404, detail="Card not found")
    
    new_lock_status = not card["is_locked"]
    
    await db.virtual_cards.update_one(
        {"user_id": current_user.user_id},
        {"$set": {"is_locked": new_lock_status}}
    )
    
    return {
        "message": f"Card {'locked' if new_lock_status else 'unlocked'} successfully",
        "is_locked": new_lock_status
    }

@api_router.post("/card/purchase")
async def process_card_purchase(purchase_request: CardPurchaseRequest, current_user: User = Depends(get_current_user)):
    # Check if card exists and is not locked
    card = await db.virtual_cards.find_one({"user_id": current_user.user_id})
    
    if not card:
        raise HTTPException(status_code=404, detail="Card not found")
    
    if card["is_locked"]:
        raise HTTPException(status_code=400, detail="Card is locked")
    
    # Check if user has sufficient balance
    user_doc = await db.users.find_one({"user_id": current_user.user_id})
    current_balance = user_doc.get("balance", 0.0)
    
    if current_balance < purchase_request.amount:
        raise HTTPException(status_code=400, detail=f"Insufficient balance. Current: ${current_balance:.2f}, Required: ${purchase_request.amount:.2f}")
    
    # Process the purchase
    transaction = Transaction(
        sender_id=current_user.user_id,
        amount=purchase_request.amount,
        transaction_type="card_purchase",
        status="completed",
        description=f"Purchase at {purchase_request.merchant}",
        completed_at=datetime.utcnow(),
        card_id=card["card_id"]
    )
    
    # Update user balance
    await db.users.update_one(
        {"user_id": current_user.user_id},
        {"$inc": {"balance": -purchase_request.amount}}
    )
    
    # Update monthly spend
    await db.virtual_cards.update_one(
        {"user_id": current_user.user_id},
        {"$inc": {"monthly_spend": purchase_request.amount}}
    )
    
    # Save transaction
    await db.transactions.insert_one(transaction.dict())
    
    return {
        "message": "Purchase completed successfully",
        "transaction_id": transaction.transaction_id,
        "amount": purchase_request.amount,
        "merchant": purchase_request.merchant,
        "new_balance": current_balance - purchase_request.amount
    }

@api_router.get("/card/spending")
async def get_card_spending(current_user: User = Depends(get_current_user)):
    # Get current month's spending
    start_of_month = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    card_transactions = await db.transactions.find({
        "sender_id": current_user.user_id,
        "transaction_type": "card_purchase",
        "created_at": {"$gte": start_of_month}
    }).to_list(100)
    
    total_spent = sum(txn["amount"] for txn in card_transactions)
    
    # Get top merchants
    merchant_spending = {}
    for txn in card_transactions:
        merchant = txn.get("description", "Unknown").replace("Purchase at ", "")
        merchant_spending[merchant] = merchant_spending.get(merchant, 0) + txn["amount"]
    
    top_merchants = sorted(merchant_spending.items(), key=lambda x: x[1], reverse=True)[:5]
    
    return {
        "monthly_total": total_spent,
        "transaction_count": len(card_transactions),
        "top_merchants": [{"name": name, "amount": amount} for name, amount in top_merchants],
        "current_month": start_of_month.strftime("%B %Y")
    }

# Payment Routes (existing ones)
@api_router.post("/payments/send")
async def send_money(send_request: SendMoneyRequest, current_user: User = Depends(get_current_user)):
    if send_request.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")
    
    # Calculate fee (0.5%)
    fee = send_request.amount * 0.005
    total_amount = send_request.amount + fee
    
    # Get current user balance from database
    user_doc = await db.users.find_one({"user_id": current_user.user_id})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")
    
    current_balance = user_doc.get("balance", 0.0)
    
    if current_balance < total_amount:
        raise HTTPException(status_code=400, detail=f"Insufficient balance. Current: ${current_balance:.2f}, Required: ${total_amount:.2f}")
    
    # Find recipient
    recipient = await db.users.find_one({
        "$or": [
            {"email": send_request.recipient_identifier},
            {"phone": send_request.recipient_identifier},
            {"username": send_request.recipient_identifier}
        ]
    })
    
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")
    
    if recipient["user_id"] == current_user.user_id:
        raise HTTPException(status_code=400, detail="Cannot send money to yourself")
    
    # Create transaction
    transaction = Transaction(
        sender_id=current_user.user_id,
        recipient_id=recipient["user_id"],
        recipient_identifier=send_request.recipient_identifier,
        amount=send_request.amount,
        fee=fee,
        transaction_type="send",
        status="completed",
        description=send_request.description,
        completed_at=datetime.utcnow()
    )
    
    # Update sender balance
    sender_result = await db.users.update_one(
        {"user_id": current_user.user_id},
        {"$inc": {"balance": -total_amount}}
    )
    
    # Update recipient balance
    recipient_result = await db.users.update_one(
        {"user_id": recipient["user_id"]},
        {"$inc": {"balance": send_request.amount}}
    )
    
    if sender_result.modified_count == 0 or recipient_result.modified_count == 0:
        raise HTTPException(status_code=400, detail="Failed to update balances")
    
    # Save transaction
    await db.transactions.insert_one(transaction.dict())
    
    return {
        "message": "Money sent successfully",
        "transaction_id": transaction.transaction_id,
        "amount": send_request.amount,
        "fee": fee,
        "recipient": recipient["username"]
    }

# NEW: Request Money Routes
@api_router.post("/payments/request")
async def request_money(request_data: RequestMoneyRequest, current_user: User = Depends(get_current_user)):
    if request_data.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")
    
    # Find requestee (person who will pay)
    requestee = await db.users.find_one({
        "$or": [
            {"email": request_data.requestee_identifier},
            {"phone": request_data.requestee_identifier},
            {"username": request_data.requestee_identifier}
        ]
    })
    
    if not requestee:
        raise HTTPException(status_code=404, detail="User not found")
    
    if requestee["user_id"] == current_user.user_id:
        raise HTTPException(status_code=400, detail="Cannot request money from yourself")
    
    # Create money request
    money_request = MoneyRequest(
        requester_id=current_user.user_id,
        requestee_id=requestee["user_id"],
        requestee_identifier=request_data.requestee_identifier,
        amount=request_data.amount,
        description=request_data.description
    )
    
    # Save request
    await db.money_requests.insert_one(money_request.dict())
    
    return {
        "message": "Money request sent successfully",
        "request_id": money_request.request_id,
        "amount": request_data.amount,
        "requestee": requestee["username"]
    }

@api_router.get("/payments/requests/sent")
async def get_sent_requests(current_user: User = Depends(get_current_user)):
    # Get requests sent by current user
    requests = await db.money_requests.find({
        "requester_id": current_user.user_id
    }).sort("created_at", -1).to_list(100)
    
    # Get requestee info for each request
    formatted_requests = []
    for req in requests:
        requestee = await db.users.find_one({"user_id": req["requestee_id"]})
        formatted_requests.append({
            "request_id": req["request_id"],
            "amount": req["amount"],
            "description": req.get("description", ""),
            "status": req["status"],
            "created_at": req["created_at"],
            "expires_at": req["expires_at"],
            "requestee": {
                "username": requestee["username"],
                "profile_picture": requestee.get("profile_picture")
            }
        })
    
    return formatted_requests

@api_router.get("/payments/requests/received")
async def get_received_requests(current_user: User = Depends(get_current_user)):
    # Get requests received by current user
    requests = await db.money_requests.find({
        "requestee_id": current_user.user_id,
        "status": "pending"
    }).sort("created_at", -1).to_list(100)
    
    # Get requester info for each request
    formatted_requests = []
    for req in requests:
        requester = await db.users.find_one({"user_id": req["requester_id"]})
        formatted_requests.append({
            "request_id": req["request_id"],
            "amount": req["amount"],
            "description": req.get("description", ""),
            "status": req["status"],
            "created_at": req["created_at"],
            "expires_at": req["expires_at"],
            "requester": {
                "username": requester["username"],
                "profile_picture": requester.get("profile_picture")
            }
        })
    
    return formatted_requests

@api_router.post("/payments/requests/pay")
async def pay_request(pay_request: PayRequestRequest, current_user: User = Depends(get_current_user)):
    # Find the money request
    request_doc = await db.money_requests.find_one({
        "request_id": pay_request.request_id,
        "requestee_id": current_user.user_id,
        "status": "pending"
    })
    
    if not request_doc:
        raise HTTPException(status_code=404, detail="Request not found or already processed")
    
    # Get current user balance
    user_doc = await db.users.find_one({"user_id": current_user.user_id})
    current_balance = user_doc.get("balance", 0.0)
    
    # Calculate fee and total
    fee = request_doc["amount"] * 0.005
    total_amount = request_doc["amount"] + fee
    
    if current_balance < total_amount:
        raise HTTPException(status_code=400, detail=f"Insufficient balance. Current: ${current_balance:.2f}, Required: ${total_amount:.2f}")
    
    # Update balances
    await db.users.update_one(
        {"user_id": current_user.user_id},
        {"$inc": {"balance": -total_amount}}
    )
    
    await db.users.update_one(
        {"user_id": request_doc["requester_id"]},
        {"$inc": {"balance": request_doc["amount"]}}
    )
    
    # Mark request as paid
    await db.money_requests.update_one(
        {"request_id": pay_request.request_id},
        {"$set": {"status": "paid"}}
    )
    
    # Create transaction record
    transaction = Transaction(
        sender_id=current_user.user_id,
        recipient_id=request_doc["requester_id"],
        amount=request_doc["amount"],
        fee=fee,
        transaction_type="send",
        status="completed",
        description=f"Payment for request: {request_doc.get('description', '')}",
        completed_at=datetime.utcnow()
    )
    
    await db.transactions.insert_one(transaction.dict())
    
    return {
        "message": "Request paid successfully",
        "transaction_id": transaction.transaction_id,
        "amount": request_doc["amount"],
        "fee": fee
    }

@api_router.post("/payments/add-funds")
async def add_funds(add_funds_request: AddFundsRequest, current_user: User = Depends(get_current_user)):
    try:
        # For demo purposes, mock successful payment
        # In production, you would create actual Stripe payment intent
        
        # Update user balance
        result = await db.users.update_one(
            {"user_id": current_user.user_id},
            {"$inc": {"balance": add_funds_request.amount}}
        )
        
        if result.modified_count == 0:
            raise HTTPException(status_code=400, detail="Failed to update balance")
        
        # Create transaction record
        transaction = Transaction(
            sender_id=current_user.user_id,
            amount=add_funds_request.amount,
            transaction_type="add_funds",
            status="completed",
            description="Added funds via card",
            completed_at=datetime.utcnow(),
            stripe_payment_intent_id=f"pi_demo_{uuid.uuid4().hex[:16]}"
        )
        
        await db.transactions.insert_one(transaction.dict())
        
        # Get updated user balance
        updated_user = await db.users.find_one({"user_id": current_user.user_id})
        
        return {
            "message": "Funds added successfully",
            "amount": add_funds_request.amount,
            "new_balance": updated_user["balance"]
        }
            
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Connected Accounts Routes
@api_router.post("/accounts/connect")
async def connect_account(connect_request: ConnectAccountRequest, current_user: User = Depends(get_current_user)):
    try:
        # In a real implementation, you'd use Stripe Connect or similar service
        # For demo purposes, we'll create a mock connected account
        
        connected_account = ConnectedAccount(
            user_id=current_user.user_id,
            account_type=connect_request.account_type,
            account_name=connect_request.account_name,
            last_four="1234",  # Mock last four digits
            stripe_account_id=f"acct_{uuid.uuid4().hex[:16]}"
        )
        
        await db.connected_accounts.insert_one(connected_account.dict())
        
        return {
            "message": "Account connected successfully",
            "account_id": connected_account.account_id,
            "account_name": connected_account.account_name,
            "account_type": connected_account.account_type
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.get("/accounts/connected")
async def get_connected_accounts(current_user: User = Depends(get_current_user)):
    accounts = await db.connected_accounts.find({"user_id": current_user.user_id}).to_list(100)
    
    return [{
        "account_id": account["account_id"],
        "account_name": account["account_name"],
        "account_type": account["account_type"],
        "last_four": account["last_four"],
        "is_default": account["is_default"]
    } for account in accounts]

@api_router.post("/payments/withdraw")
async def withdraw_money(withdraw_request: WithdrawRequest, current_user: User = Depends(get_current_user)):
    if withdraw_request.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")
    
    # Get current user balance from database
    user_doc = await db.users.find_one({"user_id": current_user.user_id})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")
    
    current_balance = user_doc.get("balance", 0.0)
    
    # Calculate fee for instant transfers
    fee = 0.0
    if withdraw_request.transfer_speed == 'instant':
        fee = max(0.25, withdraw_request.amount * 0.015)  # $0.25 or 1.5%, whichever is higher
    
    total_amount = withdraw_request.amount + fee
    
    if current_balance < total_amount:
        raise HTTPException(status_code=400, detail=f"Insufficient balance. Current: ${current_balance:.2f}, Required: ${total_amount:.2f}")
    
    # Find connected account
    account = await db.connected_accounts.find_one({
        "account_id": withdraw_request.account_id,
        "user_id": current_user.user_id
    })
    
    if not account:
        raise HTTPException(status_code=404, detail="Connected account not found")
    
    # Create withdrawal transaction
    transaction = Transaction(
        sender_id=current_user.user_id,
        amount=withdraw_request.amount,
        fee=fee,
        transaction_type="withdraw",
        status="completed",  # Demo: mark as completed immediately
        description=f"Withdrawal to {account['account_name']} ({withdraw_request.transfer_speed})",
        completed_at=datetime.utcnow()
    )
    
    # Update user balance
    result = await db.users.update_one(
        {"user_id": current_user.user_id},
        {"$inc": {"balance": -total_amount}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=400, detail="Failed to update balance")
    
    # Save transaction
    await db.transactions.insert_one(transaction.dict())
    
    return {
        "message": "Withdrawal completed successfully",
        "transaction_id": transaction.transaction_id,
        "amount": withdraw_request.amount,
        "fee": fee,
        "transfer_speed": withdraw_request.transfer_speed,
        "estimated_arrival": "1-3 business days" if withdraw_request.transfer_speed == 'standard' else "Within minutes"
    }

# Transaction History
@api_router.get("/transactions")
async def get_transactions(current_user: User = Depends(get_current_user), limit: int = 50):
    transactions = await db.transactions.find({
        "$or": [
            {"sender_id": current_user.user_id},
            {"recipient_id": current_user.user_id}
        ]
    }).sort("created_at", -1).limit(limit).to_list(limit)
    
    # Format transactions for frontend with user info
    formatted_transactions = []
    for txn in transactions:
        formatted_txn = {
            "transaction_id": txn["transaction_id"],
            "amount": txn["amount"],
            "fee": txn.get("fee", 0),
            "type": txn["transaction_type"],
            "status": txn["status"],
            "description": txn.get("description", ""),
            "created_at": txn["created_at"],
            "is_outgoing": txn["sender_id"] == current_user.user_id
        }
        
        # Add sender/recipient info with profile pictures
        if formatted_txn["is_outgoing"] and txn.get("recipient_id"):
            # Outgoing transaction - get recipient info
            recipient = await db.users.find_one({"user_id": txn["recipient_id"]})
            if recipient:
                formatted_txn["recipient"] = {
                    "username": recipient["username"],
                    "profile_picture": recipient.get("profile_picture")
                }
        elif not formatted_txn["is_outgoing"] and txn.get("sender_id") != current_user.user_id:
            # Incoming transaction - get sender info
            sender = await db.users.find_one({"user_id": txn["sender_id"]})
            if sender:
                formatted_txn["sender"] = {
                    "username": sender["username"],
                    "profile_picture": sender.get("profile_picture")
                }
        
        formatted_transactions.append(formatted_txn)
    
    return formatted_transactions

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
