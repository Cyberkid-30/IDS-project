from sqlalchemy import Column, String, Boolean
from app.database.base import Base, IDMixin, TimestampMixin


class User(Base, IDMixin, TimestampMixin):
    __tablename__ = "users"

    username = Column(
        String(50), unique=True, nullable=False, index=True, doc="Unique username"
    )
    hashed_password = Column(String(255), nullable=False, doc="Argon2 hashed password")
    is_active = Column(
        Boolean, default=True, nullable=False, doc="Whether user is active"
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, username='{self.username}')>"
