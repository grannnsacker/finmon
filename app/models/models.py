from sqlalchemy import Boolean, Column, Integer, String, ForeignKey, DateTime, Float
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    favorites = relationship("Favorite", back_populates="owner")


class Favorite(Base):
    __tablename__ = "favorites"

    id = Column(Integer, primary_key=True, index=True)
    symbol = Column(String, index=True)
    asset_type = Column(String)  # "stock" or "crypto"
    user_id = Column(Integer, ForeignKey("users.id"))
    added_date = Column(DateTime, default=datetime.utcnow)
    owner = relationship("User", back_populates="favorites")
