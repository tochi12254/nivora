# # backend/app/services/password_recovery.py
# from fastapi import BackgroundTasks, HTTPException, status
# from sqlalchemy.orm import Session

# from ..core.security import (
#     generate_password_reset_token,
#     verify_password_reset_token,
#     get_password_hash,
# )
# from ..models.user import User
# from ..schemas.auth import PasswordResetRequest, NewPasswordRequest
# from .email import send_password_reset_email


# async def request_password_reset(
#     email: str, db: Session, background_tasks: BackgroundTasks
# ):
#     user = db.query(User).filter(User.email == email).first()
#     if not user:
#         # Still return success to prevent email enumeration
#         return {"message": "If this email exists, you'll receive a reset link"}

#     reset_token = generate_password_reset_token(email)
#     await send_password_reset_email(email, reset_token, background_tasks)
#     return {"message": "If this email exists, you'll receive a reset link"}


# async def reset_password(token: str, new_password: str, db: Session):
#     email = verify_password_reset_token(token)
#     if not email:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token"
#         )

#     user = db.query(User).filter(User.email == email).first()
#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
#         )

#     hashed_password = get_password_hash(new_password)
#     user.hashed_password = hashed_password
#     db.commit()
#     return {"message": "Password updated successfully"}
