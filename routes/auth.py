from fastapi import APIRouter, HTTPException, status, Depends
from config.firebase import db
from models.schemas import (
    RegisterRequest, LoginRequest, ForgotPasswordRequest,
    VerifyOTPRequest, ResetPasswordRequest, ChangePasswordRequest
)
from utils.jwt_handler import create_access_token
from utils.password_handler import hash_password, verify_password
from utils.email_handler import generate_otp, send_otp_email
from middleware.auth_middleware import get_current_user
from datetime import datetime, timedelta

router = APIRouter(prefix="/auth", tags=["Auth"])


# ─── Register ───────────────────────────────────────────────
@router.post("/register")
async def register(body: RegisterRequest):
    users_ref = db.collection("users")
    existing = users_ref.where("email", "==", body.email).limit(1).get()

    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user_data = {
        "full_name": body.full_name,
        "email": body.email,
        "password": hash_password(body.password),
        "phone": body.phone or "",
        "profile_image": "",
        "created_at": datetime.utcnow().isoformat(),
    }

    doc_ref = users_ref.add(user_data)
    user_id = doc_ref[1].id

    token = create_access_token({"sub": user_id, "email": body.email})

    return {
        "message": "Registration successful",
        "token": token,
        "user": {
            "id": user_id,
            "full_name": body.full_name,
            "email": body.email,
            "phone": body.phone or "",
        },
    }


# ─── Login ──────────────────────────────────────────────────
@router.post("/login")
async def login(body: LoginRequest):
    users_ref = db.collection("users")
    docs = users_ref.where("email", "==", body.email).limit(1).get()

    if not docs:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    user_doc = docs[0]
    user = user_doc.to_dict()

    if not verify_password(body.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token({"sub": user_doc.id, "email": user["email"]})

    return {
        "message": "Login successful",
        "token": token,
        "user": {
            "id": user_doc.id,
            "full_name": user["full_name"],
            "email": user["email"],
            "phone": user.get("phone", ""),
            "profile_image": user.get("profile_image", ""),
        },
    }


# ─── Forgot Password ────────────────────────────────────────
@router.post("/forgot-password")
async def forgot_password(body: ForgotPasswordRequest):
    users_ref = db.collection("users")
    docs = users_ref.where("email", "==", body.email).limit(1).get()

    if not docs:
        raise HTTPException(status_code=404, detail="Email not found")

    otp = generate_otp()
    expiry = (datetime.utcnow() + timedelta(minutes=10)).isoformat()

    db.collection("otps").document(body.email).set({
        "otp": otp,
        "expires_at": expiry,
        "verified": False,
    })

    sent = send_otp_email(body.email, otp)
    if not sent:
        raise HTTPException(status_code=500, detail="Failed to send OTP email")

    return {"message": "OTP sent to your email"}


# ─── Verify OTP ─────────────────────────────────────────────
@router.post("/verify-otp")
async def verify_otp(body: VerifyOTPRequest):
    otp_doc = db.collection("otps").document(body.email).get()

    if not otp_doc.exists:
        raise HTTPException(status_code=400, detail="OTP not found")

    otp_data = otp_doc.to_dict()

    if datetime.utcnow().isoformat() > otp_data["expires_at"]:
        raise HTTPException(status_code=400, detail="OTP expired")

    if otp_data["otp"] != body.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    db.collection("otps").document(body.email).update({"verified": True})

    return {"message": "OTP verified successfully"}


# ─── Reset Password ─────────────────────────────────────────
@router.post("/reset-password")
async def reset_password(body: ResetPasswordRequest):
    otp_doc = db.collection("otps").document(body.email).get()

    if not otp_doc.exists:
        raise HTTPException(status_code=400, detail="OTP not found")

    otp_data = otp_doc.to_dict()

    if not otp_data.get("verified"):
        raise HTTPException(status_code=400, detail="OTP not verified")

    if otp_data["otp"] != body.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    users_ref = db.collection("users")
    docs = users_ref.where("email", "==", body.email).limit(1).get()

    if not docs:
        raise HTTPException(status_code=404, detail="User not found")

    user_doc = docs[0]
    user_doc.reference.update({"password": hash_password(body.new_password)})

    db.collection("otps").document(body.email).delete()

    return {"message": "Password reset successful"}


# ─── Change Password (logged in) ────────────────────────────
@router.post("/change-password")
async def change_password(body: ChangePasswordRequest, current_user: dict = Depends(get_current_user)):
    user_id = current_user["sub"]
    user_doc = db.collection("users").document(user_id).get()

    if not user_doc.exists:
        raise HTTPException(status_code=404, detail="User not found")

    user = user_doc.to_dict()

    if not verify_password(body.old_password, user["password"]):
        raise HTTPException(status_code=400, detail="Old password is incorrect")

    db.collection("users").document(user_id).update({
        "password": hash_password(body.new_password)
    })

    return {"message": "Password changed successfully"}
