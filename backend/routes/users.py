from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app import crud, auth, dependencies
from datetime import timedelta
from schemas import user as schemas
from models import user as models
router = APIRouter()
from fastapi.responses import HTMLResponse
from app.auth import get_password_hash  # correct import


# Index route
@router.get("/", response_class=HTMLResponse)
async def index():
    return """
    <html>
        <head>
            <title>Real-Time Notes API</title>
        </head>
        <body>
            <h1>Welcome to the Real-Time Notes API</h1>
            <p>This API allows you to manage notes in real time. You can create, read, update, and delete notes.</p>
            <h3>API Endpoints</h3>
            <ul>
                <li><b>POST /login</b> - Login to the application</li>
                <li><b>POST /register</b> - Register a new user</li>
                <li><b>GET /notes</b> - Get all notes (authenticated)</li>
                <li><b>POST /notes</b> - Create a new note (authenticated)</li>
                <li><b>PUT /notes/{note_id}</b> - Update a note (authenticated)</li>
                <li><b>DELETE /notes/{note_id}</b> - Delete a note (authenticated)</li>
            </ul>
            <p>To interact with this API, use the endpoints listed above.</p>
        </body>
    </html>
    """


@router.get("/test-create-user")
def test_create_user(db: Session = Depends(dependencies.get_db)):


    test_email = "heyhey@example.com"
    test_password = "123456"

    existing = db.query(models.User).filter(models.User.email == test_email).first()
    if existing:
        return {"message": "User already exists", "user_id": existing.id}

    hashed_pw = get_password_hash(test_password)  # correct usage
    new_user = models.User(email=test_email, hashed_password=hashed_pw)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "Test user created",
        "user": {
            "id": new_user.id,
            "email": new_user.email,
            "hashed_password": new_user.hashed_password,
        },
    }


@router.post("/register", response_model=schemas.UserResponse)
def register(user: schemas.UserCreate, db: Session = Depends(dependencies.get_db)):
    existing = crud.get_user_by_email(db, email=user.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    return crud.create_user(db, user)


@router.post("/login", response_model=schemas.Token)
def login(data: schemas.UserLogin, db: Session = Depends(dependencies.get_db)):
    print("User trying to login")
    user = crud.authenticate_user(db, email=data.email, password=data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect credentials")
    token = auth.create_access_token(
        data={"sub": user.email}, expires_delta=timedelta(minutes=30)
    )
    return {"access_token": token, "token_type": "bearer"}

