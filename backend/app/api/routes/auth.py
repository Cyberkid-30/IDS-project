from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.auth_deps import get_current_user
from app.api.deps import get_database
from app.core.auth import create_access_token, hash_password, verify_password
from app.core.logging import ids_logger
from app.models.user import User
from app.schemas.user import UserCreate, UserResponse, Token

router = APIRouter()


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Create a new user account.",
)
def register(
    user_data: UserCreate,
    db: Session = Depends(get_database),
):
    existing = db.query(User).filter(User.username == user_data.username).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken",
        )

    user = User(
        username=user_data.username,
        hashed_password=hash_password(user_data.password),
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    ids_logger.info(f"User registered: {user.username}")
    return user


@router.post(
    "/login",
    response_model=Token,
    summary="Login",
    description="Authenticate and get a JWT access token.",
)
def login(
    user_data: UserCreate,
    db: Session = Depends(get_database),
):
    user = db.query(User).filter(User.username == user_data.username).first()
    if not user or not verify_password(user_data.password, user.hashed_password):  # type: ignore
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    if not user.is_active:  # type: ignore
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive",
        )

    access_token = create_access_token(data={"sub": user.username})
    ids_logger.info(f"User logged in: {user.username}")
    return Token(access_token=access_token, token_type="bearer")


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user",
    description="Get the currently authenticated user's details.",
)
def get_me(
    current_user: User = Depends(get_current_user),
):
    return current_user
