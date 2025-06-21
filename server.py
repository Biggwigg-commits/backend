from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from emergentintegrations.payments.stripe.checkout import StripeCheckout, CheckoutSessionResponse, CheckoutStatusResponse, CheckoutSessionRequest
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
import uuid
from datetime import datetime
import hashlib
import jwt
from passlib.context import CryptContext

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Security
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
JWT_SECRET = "your-secret-key"  # In production, use a secure secret

# Stripe Setup
STRIPE_API_KEY = os.environ.get('STRIPE_API_KEY')
stripe_checkout = StripeCheckout(api_key=STRIPE_API_KEY)

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")

# User Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    email: str
    phone: Optional[str] = None
    password_hash: str
    balance: float = 0.0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = True

class UserCreate(BaseModel):
    username: str
    email: str
    phone: Optional[str] = None
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    phone: Optional[str] = None
    balance: float
    created_at: datetime

# Transaction Models
class Transaction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    from_user_id: str
    to_user_id: Optional[str] = None
    to_email: Optional[str] = None
    amount: float
    transaction_type: str  # "send", "receive", "add_funds", "withdraw"
    status: str  # "pending", "completed", "failed", "cancelled"
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    stripe_session_id: Optional[str] = None

class PaymentTransaction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    amount: float
    currency: str = "usd"
    session_id: str
    payment_status: str = "pending"
    status: str = "initiated"
    metadata: Optional[Dict[str, str]] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class SendMoneyRequest(BaseModel):
    to_email: str
    amount: float
    description: Optional[str] = None

class AddFundsRequest(BaseModel):
    amount: float

# Utility Functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(user_id: str) -> str:
    payload = {"user_id": user_id, "exp": datetime.utcnow().timestamp() + 86400}  # 24 hours
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=["HS256"])
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = await db.users.find_one({"id": user_id})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        return User(**user)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# API Routes
@api_router.get("/")
async def root():
    return {"message": "PayMe API is running", "status": "healthy"}

# Auth Routes
@api_router.post("/auth/register")
async def register(user_data: UserCreate):
    # Check if user exists
    existing_user = await db.users.find_one({"$or": [{"email": user_data.email}, {"username": user_data.username}]})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Create user
    user = User(
        username=user_data.username,
        email=user_data.email,
        phone=user_data.phone,
        password_hash=hash_password(user_data.password)
    )
    
    await db.users.insert_one(user.dict())
    
    # Create access token
    token = create_access_token(user.id)
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": UserResponse(**user.dict())
    }

@api_router.post("/auth/login")
async def login(login_data: UserLogin):
    user = await db.users.find_one({"email": login_data.email})
    if not user or not verify_password(login_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token(user["id"])
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": UserResponse(**user)
    }

# User Routes
@api_router.get("/user/profile", response_model=UserResponse)
async def get_profile(current_user: User = Depends(get_current_user)):
    return UserResponse(**current_user.dict())

@api_router.get("/user/balance")
async def get_balance(current_user: User = Depends(get_current_user)):
    return {"balance": current_user.balance}

# Payment Routes
@api_router.post("/payments/add-funds")
async def add_funds(request: AddFundsRequest, current_user: User = Depends(get_current_user)):
    # Create Stripe checkout session for adding funds
    origin_url = "https://6cb1da09-4669-467d-a0cd-136728a7aed1.preview.emergentagent.com"  # Get from request header in production
    
    success_url = f"{origin_url}/add-funds-success?session_id={{CHECKOUT_SESSION_ID}}"
    cancel_url = f"{origin_url}/dashboard"
    
    checkout_request = CheckoutSessionRequest(
        amount=request.amount,
        currency="usd",
        success_url=success_url,
        cancel_url=cancel_url,
        metadata={
            "user_id": current_user.id,
            "transaction_type": "add_funds"
        }
    )
    
    session = await stripe_checkout.create_checkout_session(checkout_request)
    
    # Store payment transaction
    payment_transaction = PaymentTransaction(
        user_id=current_user.id,
        amount=request.amount,
        session_id=session.session_id,
        metadata={"transaction_type": "add_funds"}
    )
    
    await db.payment_transactions.insert_one(payment_transaction.dict())
    
    return {"checkout_url": session.url, "session_id": session.session_id}

@api_router.get("/payments/status/{session_id}")
async def check_payment_status(session_id: str, current_user: User = Depends(get_current_user)):
    # Check payment status with Stripe
    checkout_status = await stripe_checkout.get_checkout_status(session_id)
    
    # Update payment transaction in database
    payment_transaction = await db.payment_transactions.find_one({"session_id": session_id})
    if not payment_transaction:
        raise HTTPException(status_code=404, detail="Payment transaction not found")
    
    # Update transaction status
    await db.payment_transactions.update_one(
        {"session_id": session_id},
        {"$set": {
            "status": checkout_status.status,
            "payment_status": checkout_status.payment_status
        }}
    )
    
    # If payment is successful, add funds to user balance
    if checkout_status.payment_status == "paid" and payment_transaction["payment_status"] != "paid":
        amount = checkout_status.amount_total / 100  # Convert from cents
        
        # Update user balance
        await db.users.update_one(
            {"id": current_user.id},
            {"$inc": {"balance": amount}}
        )
        
        # Create transaction record
        transaction = Transaction(
            from_user_id=current_user.id,
            amount=amount,
            transaction_type="add_funds",
            status="completed",
            description="Funds added via card",
            stripe_session_id=session_id
        )
        
        await db.transactions.insert_one(transaction.dict())
    
    return {
        "status": checkout_status.status,
        "payment_status": checkout_status.payment_status,
        "amount": checkout_status.amount_total / 100
    }

@api_router.post("/payments/send")
async def send_money(request: SendMoneyRequest, current_user: User = Depends(get_current_user)):
    # Check if sender has sufficient balance
    if current_user.balance < request.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    
    # Find recipient by email
    recipient = await db.users.find_one({"email": request.to_email})
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")
    
    # Create transaction
    transaction = Transaction(
        from_user_id=current_user.id,
        to_user_id=recipient["id"],
        to_email=request.to_email,
        amount=request.amount,
        transaction_type="send",
        status="completed",
        description=request.description
    )
    
    # Update balances
    await db.users.update_one(
        {"id": current_user.id},
        {"$inc": {"balance": -request.amount}}
    )
    
    await db.users.update_one(
        {"id": recipient["id"]},
        {"$inc": {"balance": request.amount}}
    )
    
    # Save transaction
    await db.transactions.insert_one(transaction.dict())
    
    return {"message": "Money sent successfully", "transaction_id": transaction.id}

@api_router.get("/transactions", response_model=List[Transaction])
async def get_transactions(current_user: User = Depends(get_current_user)):
    transactions = await db.transactions.find({
        "$or": [
            {"from_user_id": current_user.id},
            {"to_user_id": current_user.id}
        ]
    }).sort("created_at", -1).limit(50).to_list(50)
    
    return [Transaction(**transaction) for transaction in transactions]

# Search users
@api_router.get("/users/search")
async def search_users(q: str, current_user: User = Depends(get_current_user)):
    users = await db.users.find({
        "$and": [
            {"id": {"$ne": current_user.id}},  # Exclude current user
            {"$or": [
                {"username": {"$regex": q, "$options": "i"}},
                {"email": {"$regex": q, "$options": "i"}}
            ]}
        ]
    }).limit(10).to_list(10)
    
    return [{"id": user["id"], "username": user["username"], "email": user["email"]} for user in users]

# Include router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
