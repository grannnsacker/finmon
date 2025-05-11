from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime

class FavoriteBase(BaseModel):
    symbol: str
    asset_type: str

class FavoriteCreate(FavoriteBase):
    pass

class Favorite(BaseModel):
    id: int
    symbol: str
    asset_type: str
    user_id: int
    added_date: datetime

    class Config:
        orm_mode = True

class UserBase(BaseModel):
    email: EmailStr
    username: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    is_active: bool
    favorites: Optional[List[Favorite]] = []

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None


class Notification(BaseModel):
    id: int
    type: int
    user_id: int
    symbol: str
    desire_price: float