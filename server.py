from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import stripe
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
JWT_SECRET = "payme-secret-key-2025"

# Stripe Setup
STRIPE_API_KEY = os.environ.get('STRIPE_API_KEY')
stripe.api_key = STRIPE_API_KEY

# Create the main app
app = FastAPI(title="PayMe API", version="2.0.0")
api_router = APIRouter(prefix="/api")

# User Models - Cash App/PayPal Style
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    email: str
    phone: str  # Required like Cash App
    password_hash: str
    balance: float = 0.0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = True
    profile_complete: bool = True

class UserCreate(BaseModel):
    username: str
    email: str
    phone: str
    password: str

class UserLogin(BaseModel):
    identifier: str  # Email or Phone
    password: str

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    phone: str
    balance: float
    created_at: datetime

# Transaction Models - Production Grade
class Transaction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    from_user_id: str
    to_user_id: Optional[str] = None
    to_identifier: Optional[str] = None  # Email or Phone
    amount: float
    transaction_type: str
    status: str
    description: Optional[str] = None
    fee_amount: float = 0.0
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
    to_identifier: str  # Email or Phone
    amount: float
    description: Optional[str] = None

class AddFundsRequest(BaseModel):
    amount: float

# Utility Functions - Production Grade
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(user_id: str) -> str:
    payload = {"user_id": user_id, "exp": datetime.utcnow().timestamp() + 86400}
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

def calculate_fee(amount: float) -> float:
    """Calculate 0.5% fee like Cash App"""
    return round(amount * 0.005, 2)

# API Routes - Cash App/PayPal Architecture
@api_router.get("/")
async def root():
    return {"message": "PayMe API v2.0", "status": "healthy", "timestamp": datetime.utcnow()}

@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "service": "PayMe", "version": "2.0.0"}

# Authentication Routes - Production Grade
@api_router.post("/auth/register")
async def register(user_data: UserCreate):
    # Validate input
    if not user_data.username or not user_data.email or not user_data.phone or not user_data.password:
        raise HTTPException(status_code=400, detail="All fields are required")
    
    # Clean phone number
    phone = user_data.phone.strip()
    if not phone.startswith('+'):
        phone = '+' + phone.lstrip('+1')
    
    # Check if user exists
    existing_user = await db.users.find_one({
        "$or": [
            {"email": user_data.email.lower()}, 
            {"username": user_data.username.lower()},
            {"phone": phone}
        ]
    })
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists with this email, username, or phone")
    
    # Create user
    user = User(
        username=user_data.username.strip(),
        email=user_data.email.lower().strip(),
        phone=phone,
        password_hash=hash_password(user_data.password)
    )
    
    await db.users.insert_one(user.dict())
    
    # Create access token
    token = create_access_token(user.id)
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": UserResponse(**user.dict()),
        "message": "Account created successfully"
    }

@api_router.post("/auth/login")
async def login(login_data: UserLogin):
    # Find user by email OR phone
    identifier = login_data.identifier.strip().lower()
    
    # Try to find by email first, then phone
    user = await db.users.find_one({
        "$or": [
            {"email": identifier},
            {"phone": login_data.identifier.strip()}
        ]
    })
    
    if not user or not verify_password(login_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email/phone or password")
    
    token = create_access_token(user["id"])
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": UserResponse(**user),
        "message": "Login successful"
    }

# User Routes - PayPal Style
@api_router.get("/user/profile", response_model=UserResponse)
async def get_profile(current_user: User = Depends(get_current_user)):
    return UserResponse(**current_user.dict())

@api_router.get("/user/balance")
async def get_balance(current_user: User = Depends(get_current_user)):
    return {"balance": current_user.balance, "currency": "USD"}

# Payment Routes - Cash App Architecture
@api_router.post("/payments/add-funds")
async def add_funds(request: AddFundsRequest, current_user: User = Depends(get_current_user)):
    if request.amount < 1:
        raise HTTPException(status_code=400, detail="Minimum amount is $1.00")
    
    # Create Stripe checkout session
    origin_url = "https://6cb1da09-4669-467d-a0cd-136728a7aed1.preview.emergentagent.com"
    
    success_url = f"{origin_url}/app/add-funds-success?session_id={{CHECKOUT_SESSION_ID}}"
    cancel_url = f"{origin_url}/app/dashboard"
    
    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': 'Add Funds to PayMe Account',
                        'description': f'Add ${request.amount:.2f} to your PayMe wallet',
                    },
                    'unit_amount': int(request.amount * 100),  # Convert to cents
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=success_url,
            cancel_url=cancel_url,
            metadata={
                'user_id': current_user.id,
                'transaction_type': 'add_funds',
                'username': current_user.username
            }
        )
        
        # Store payment transaction
        payment_transaction = PaymentTransaction(
            user_id=current_user.id,
            amount=request.amount,
            session_id=checkout_session.id,
            metadata={"transaction_type": "add_funds"}
        )
        
        await db.payment_transactions.insert_one(payment_transaction.dict())
        
        return {
            "checkout_url": checkout_session.url, 
            "session_id": checkout_session.id,
            "amount": request.amount
        }
    
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=f"Stripe error: {str(e)}")

@api_router.get("/payments/status/{session_id}")
async def check_payment_status(session_id: str, current_user: User = Depends(get_current_user)):
    try:
        # Check payment status with Stripe
        checkout_session = stripe.checkout.Session.retrieve(session_id)
        
        # Find payment transaction
        payment_transaction = await db.payment_transactions.find_one({"session_id": session_id})
        if not payment_transaction:
            raise HTTPException(status_code=404, detail="Payment transaction not found")
        
        # Update transaction status
        payment_status = "paid" if checkout_session.payment_status == "paid" else "pending"
        
        await db.payment_transactions.update_one(
            {"session_id": session_id},
            {"$set": {
                "status": checkout_session.status,
                "payment_status": payment_status
            }}
        )
        
        # If payment successful and not already processed
        if checkout_session.payment_status == "paid" and payment_transaction["payment_status"] != "paid":
            amount = checkout_session.amount_total / 100  # Convert from cents
            
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
                description="Funds added via Stripe",
                stripe_session_id=session_id,
                fee_amount=0.0
            )
            
            await db.transactions.insert_one(transaction.dict())
        
        return {
            "status": checkout_session.status,
            "payment_status": payment_status,
            "amount": checkout_session.amount_total / 100
        }
    
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=f"Stripe error: {str(e)}")

@api_router.post("/payments/send")
async def send_money(request: SendMoneyRequest, current_user: User = Depends(get_current_user)):
    # Validate amount
    if request.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be greater than 0")
    
    # Calculate fee
    fee = calculate_fee(request.amount)
    total_amount = request.amount + fee
    
    # Check if sender has sufficient balance
    if current_user.balance < total_amount:
        raise HTTPException(
            status_code=400, 
            detail=f"Insufficient balance. Need ${total_amount:.2f} (${request.amount:.2f} + ${fee:.2f} fee)"
        )
    
    # Find recipient by email OR phone
    identifier = request.to_identifier.strip()
    recipient = await db.users.find_one({
        "$or": [
            {"email": identifier.lower()},
            {"phone": identifier}
        ]
    })
    
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")
    
    if recipient["id"] == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot send money to yourself")
    
    # Create transaction
    transaction = Transaction(
        from_user_id=current_user.id,
        to_user_id=recipient["id"],
        to_identifier=identifier,
        amount=request.amount,
        transaction_type="send",
        status="completed",
        description=request.description,
        fee_amount=fee
    )
    
    # Update balances
    await db.users.update_one(
        {"id": current_user.id},
        {"$inc": {"balance": -total_amount}}
    )
    
    await db.users.update_one(
        {"id": recipient["id"]},
        {"$inc": {"balance": request.amount}}
    )
    
    # Save transaction
    await db.transactions.insert_one(transaction.dict())
    
    return {
        "message": "Money sent successfully", 
        "transaction_id": transaction.id,
        "amount": request.amount,
        "fee": fee,
        "total": total_amount,
        "recipient": {
            "username": recipient["username"],
            "identifier": identifier
        }
    }

@api_router.get("/transactions", response_model=List[Transaction])
async def get_transactions(current_user: User = Depends(get_current_user)):
    transactions = await db.transactions.find({
        "$or": [
            {"from_user_id": current_user.id},
            {"to_user_id": current_user.id}
        ]
    }).sort("created_at", -1).limit(50).to_list(50)
    
    return [Transaction(**transaction) for transaction in transactions]

# Search users - PayPal style
@api_router.get("/users/search")
async def search_users(q: str, current_user: User = Depends(get_current_user)):
    if len(q) < 2:
        return []
    
    users = await db.users.find({
        "$and": [
            {"id": {"$ne": current_user.id}},
            {"$or": [
                {"username": {"$regex": q, "$options": "i"}},
                {"email": {"$regex": q, "$options": "i"}},
                {"phone": {"$regex": q, "$options": "i"}}
            ]}
        ]
    }).limit(10).to_list(10)
    
    return [{
        "id": user["id"], 
        "username": user["username"], 
        "email": user["email"],
        "phone": user.get("phone", ""),
        "display_name": f"{user['username']} ({user['email']})"
    } for user in users]

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
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
