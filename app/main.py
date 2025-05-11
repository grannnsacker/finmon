import asyncio

from fastapi import FastAPI, Depends, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import os
from jose import JWTError, jwt

from . import models, schemas
from .database import engine, get_db
from passlib.context import CryptContext
from fastapi.responses import HTMLResponse

import redis

TTL = 60

# Create database tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# Static files and templates
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# Security
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    auto_error=False
)

# API Keys
ALPHA_VANTAGE_API_KEY = os.getenv("ALPHA_VANTAGE_API_KEY")
COINAPI_KEY = os.getenv("COINAPI_KEY")

r = redis.Redis(
    host="redis",
    port=6379,
    db=0,
    decode_responses=True  # Чтобы возвращались строки, а не bytes
)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user_or_redirect(request: Request, db: Session):
    token = request.cookies.get("access_token")
    redirect_url = f"/login?next={request.url.path}"

    if not token or not token.startswith("Bearer "):
        return RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)

    token = token.replace("Bearer ", "")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            return RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)

        user = db.query(models.User).filter(models.User.username == username).first()
        if user is None:
            return RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)

        return user
    except JWTError:
        return RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)


@app.post("/token")
async def login(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    access_token = create_access_token(data={"sub": user.username})
    
    # Set the token in an HTTP-only cookie
    response = JSONResponse(content={
        "message": "Successfully logged in",
        "username": user.username
    })
    
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax",
        max_age=1800  # 30 minutes
    )
    
    return response


@app.post("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    db_user = models.User(
        email=user.email,
        username=user.username,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.get("/search/{symbol}")
async def search_asset(symbol: str, asset_type: str):
    cached_price = r.get(symbol)
    if cached_price is not None and cached_price != "None":
        return {"price": float(cached_price), "ticker": symbol}
    else:
        try:
            if asset_type == "stock":
                price = get_price(*map[symbol])
            elif asset_type == "crypto":
                price = get_crypto_active_price(symbol)
            r.set(symbol, str(price), TTL)
            return {"price": price, "ticker": symbol}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


@app.post("/favorites/", response_model=schemas.Favorite)
async def add_favorite(
    favorite: schemas.FavoriteCreate,
    request: Request,
    db: Session = Depends(get_db)
):
    user = await get_current_user_or_redirect(request, db)
    if isinstance(user, RedirectResponse):
        return user

    existing = db.query(models.Favorite).filter_by(
        user_id=user.id,
        symbol=favorite.symbol,
        asset_type=favorite.asset_type
    ).first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Asset already in favorites"
        )

    db_favorite = models.Favorite(
        symbol=favorite.symbol,
        asset_type=favorite.asset_type,
        user_id=user.id
    )
    db.add(db_favorite)
    db.commit()
    db.refresh(db_favorite)
    return db_favorite


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/profile", response_class=HTMLResponse)
async def profile(
    request: Request,
    db: Session = Depends(get_db)
):
    user = await get_current_user_or_redirect(request, db)
    if isinstance(user, RedirectResponse):
        return user
        
    return templates.TemplateResponse(
        "profile.html",
        {"request": request, "user": user}
    )


@app.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/register")
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.get("/favorites", response_class=HTMLResponse)
async def favorites_page(
    request: Request,
    db: Session = Depends(get_db)
):
    user = await get_current_user_or_redirect(request, db)
    if isinstance(user, RedirectResponse):
        return user
        
    user_favorites = db.query(models.Favorite).filter(models.Favorite.user_id == user.id).all()
    return templates.TemplateResponse(
        "favorites.html",
        {"request": request, "user": user, "favorites": user_favorites}
    )


@app.delete("/favorites/{favorite_id}")
async def remove_favorite(
    favorite_id: int,
    request: Request,
    db: Session = Depends(get_db)
):
    user = await get_current_user_or_redirect(request, db)
    if isinstance(user, RedirectResponse):
        return user

    favorite = db.query(models.Favorite).filter(
        models.Favorite.id == favorite_id,
        models.Favorite.user_id == user.id
    ).first()

    if not favorite:
        raise HTTPException(status_code=404, detail="Favorite not found")

    db.delete(favorite)
    db.commit()
    return {"message": "Favorite removed successfully"}


@app.post("/logout")
async def logout():
    response = JSONResponse(content={"message": "Successfully logged out"})
    response.delete_cookie(key="access_token")
    return response

# Add check-auth endpoint
@app.get("/check-auth")
async def check_auth(
    request: Request,
    db: Session = Depends(get_db)
):
    user = await get_current_user_or_redirect(request, db)
    if isinstance(user, RedirectResponse):
        raise HTTPException(status_code=401)
    return {"authenticated": True}

from datetime import datetime, timedelta


@app.get("/history/{symbol}")
async def get_history(symbol: str, asset_type: str):
    if asset_type == "stock":
        data = make_candle_stock_req(symbol)
        return data

    elif asset_type == "crypto":
        return get_crypto_history(map[symbol])

    else:
        raise HTTPException(status_code=400, detail="Invalid asset type")


from dotenv import load_dotenv
import http.client
import json

OBLIGATION_TYPE = 1
STOCK_TYPE = 2
FUTURES_TYPE = 3
class Currency:
    hkd = 0
    usd = 80
    rub = 1
    eur = 90
    gbp = 0
    chf = 0
    cny = 0


load_dotenv()

from tinkoff.invest import AsyncClient, InstrumentStatus

TOKEN = os.environ["INVEST_TOKEN"]

map = dict()


def get_bonds_price(figi):
    conn = http.client.HTTPSConnection("sandbox-invest-public-api.tinkoff.ru")
    payload = json.dumps({
        "idType": "INSTRUMENT_ID_TYPE_FIGI",
        "classCode": "string",
        "id": figi
        })
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': 'Bearer ' + TOKEN
    }
    conn.request("POST", "https://invest-public-api.tinkoff.ru/rest/tinkoff.public.invest.api.contract.v1.InstrumentsService/BondBy", payload, headers)
    res = conn.getresponse()
    data = res.read()
    dataJson = json.loads(data.decode("utf-8"))
    price_info = dataJson['instrument']
    currency = price_info["currency"]
    units = int(price_info["nominal"].get("units", 0))
    nano = int(price_info["nominal"].get("nano", 0))
    price = units + nano / 1e9
    if currency == "hkd":
        price = price * Currency.hkd
    elif currency == "rub":
        price = price * Currency.rub
    elif currency == "usd":
        price = price * Currency.usd
    return price


def get_stocks_price(figi, currency):
    conn = http.client.HTTPSConnection("sandbox-invest-public-api.tinkoff.ru")
    payload = json.dumps({
    "instrumentId": [
        figi
    ],
    "lastPriceType": "LAST_PRICE_UNSPECIFIED",
    "instrumentStatus": "INSTRUMENT_STATUS_UNSPECIFIED"
    })
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': 'Bearer ' + TOKEN
    }
    conn.request("POST", "https://invest-public-api.tinkoff.ru/rest/tinkoff.public.invest.api.contract.v1.MarketDataService/GetLastPrices", payload, headers)
    res = conn.getresponse()
    data = res.read()
    dataJson = json.loads(data.decode("utf-8"))
    price_info = dataJson['lastPrices'][0]['price']
    units = int(price_info.get("units", 0))
    nano = int(price_info.get("nano", 0))
    price = units + nano / 1e9
    if currency == "hkd":
        price = price * Currency.hkd
    elif currency == "rub":
        price = price * Currency.rub
    elif currency == "usd":
        price = price * Currency.usd
    return price


def get_futures_price():
    conn = http.client.HTTPSConnection("sandbox-invest-public-api.tinkoff.ru")
    payload = json.dumps({
    "instrumentStatus": "INSTRUMENT_STATUS_UNSPECIFIED",
    "instrumentExchange": "INSTRUMENT_EXCHANGE_UNSPECIFIED"
    })
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': 'Bearer ' + TOKEN
    }
    conn.request("POST", "https://invest-public-api.tinkoff.ru/rest/tinkoff.public.invest.api.contract.v1.InstrumentsService/Bonds", payload, headers)
    res = conn.getresponse()
    data = res.read()
    dataJson = json.loads(data.decode("utf-8"))
    for i in dataJson["instruments"]:
        map[i['ticker']] = (i['figi'], i['currency'], FUTURES_TYPE)


def get_bonds():
    conn = http.client.HTTPSConnection("sandbox-invest-public-api.tinkoff.ru")
    payload = json.dumps({
    "instrumentStatus": "INSTRUMENT_STATUS_UNSPECIFIED",
    "instrumentExchange": "INSTRUMENT_EXCHANGE_UNSPECIFIED"
    })
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': 'Bearer ' + TOKEN
    }
    conn.request("POST", "https://invest-public-api.tinkoff.ru/rest/tinkoff.public.invest.api.contract.v1.InstrumentsService/Bonds", payload, headers)
    res = conn.getresponse()
    data = res.read()
    dataJson = json.loads(data.decode("utf-8"))
    for i in dataJson["instruments"]:
        map[i['ticker']] = (i['figi'], i['currency'], OBLIGATION_TYPE)


def get_stocks():
    conn = http.client.HTTPSConnection("sandbox-invest-public-api.tinkoff.ru")
    payload = json.dumps({
    "instrumentStatus": "INSTRUMENT_STATUS_UNSPECIFIED",
    "instrumentExchange": "INSTRUMENT_EXCHANGE_UNSPECIFIED"
    })
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': 'Bearer ' + TOKEN
    }
    conn.request("POST", "https://sandbox-invest-public-api.tinkoff.ru/rest/tinkoff.public.invest.api.contract.v1.InstrumentsService/Shares", payload, headers)
    res = conn.getresponse()
    data = res.read()
    dataJson = json.loads(data.decode("utf-8"))
    for i in dataJson["instruments"]:
        map[i['ticker']] = (i['figi'], i['currency'], STOCK_TYPE)


def convert_price(price_dict):
    return float(price_dict["units"]) + price_dict["nano"] / 1e9


def make_candle_stock_req(symbol):
    conn = http.client.HTTPSConnection("sandbox-invest-public-api.tinkoff.ru")
    now = datetime.utcnow()
    one_month_ago = now - timedelta(days=30)
    body = {
        "from": one_month_ago.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "to": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "interval": "CANDLE_INTERVAL_DAY",
        "instrumentId": map[symbol][0],
        "candleSourceType": "CANDLE_SOURCE_UNSPECIFIED",
        "limit": 30
    }
    payload = json.dumps(body)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + TOKEN
    }

    conn.request("POST", "https://sandbox-invest-public-api.tinkoff.ru/rest/tinkoff.public.invest.api.contract.v1.MarketDataService/GetCandles", payload, headers)
    res = conn.getresponse()
    data = res.read()

    dataJson = json.loads(data.decode("utf-8"))["candles"]

    flag = False
    if map[symbol][1] != "rub":
        flag = True
    history = [
        {
            "date": candle["time"][:10],  # '2025-05-07'
            "close": convert_price(candle["close"]) * 80 if flag else convert_price(candle["close"])
        }
        for candle in dataJson if candle["isComplete"]
    ]
    return history

def get_price(figi, currency, type):
    if type == FUTURES_TYPE:
        conn = http.client.HTTPSConnection("sandbox-invest-public-api.tinkoff.ru")
        return get_futures_price()
    elif type == STOCK_TYPE:
        return get_stocks_price(figi, currency)
    elif type == OBLIGATION_TYPE:
        return get_bonds_price(figi)
    return ""



import requests

url = "https://api.coingecko.com/api/v3/simple/price?vs_currencies=usd&precision=2&symbols="

headers = {
    "accept": "application/json",
    "x-cg-demo-api-key": "CG-JNJjdgtbGc4ty4tjnMghiNmj"
}


def get_crypto_active_price(ticker):
    response = requests.get(url+ticker, headers=headers)
    if response:
        return response.json()[ticker]["usd"] * 80
    return 100


def add_crypto_to_map():
    url = "https://api.coingecko.com/api/v3/coins/list?include_platform=false"

    headers = {
        "accept": "application/json",
        "x-cg-demo-api-key": "CG-JNJjdgtbGc4ty4tjnMghiNmj"
    }

    response = requests.get(url, headers=headers)

    for i in json.loads(response.text):
        map[i["symbol"]] = i["id"]


def get_crypto_history(id):
    url = f"https://api.coingecko.com/api/v3/coins/{id}/market_chart?vs_currency=usd&days=30&interval=daily&precision=2"
    headers = {
        "accept": "application/json",
        "x-cg-demo-api-key": "CG-JNJjdgtbGc4ty4tjnMghiNmj"
    }
    current_date = datetime.utcnow()
    response = requests.get(url, headers=headers)

    data = json.loads(response.text)

    dates_list = []
    for i in range(30):
        date = current_date - timedelta(days=i)
        formatted_date = date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        dates_list.append(formatted_date)
    d = data['prices'][::-1]
    history = [
        {
            "date":dates_list[i],
            "close": d[i][1] * 80
        }
        for i in range(len(dates_list))
    ]
    return history



def get_tickers():
    try:
        get_bonds()
    except http.client.IncompleteRead:
        pass
    get_stocks()
    add_crypto_to_map()


get_tickers()
