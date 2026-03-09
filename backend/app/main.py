# -----------------------------
# FastAPI and Middleware Imports
# -----------------------------
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from dotenv import load_dotenv  # Load environment variables
import logging

# -----------------------------
# SlowAPI: Rate Limiting Setup
# -----------------------------
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler

# -----------------------------
# Starlette Middleware for custom payload control
# -----------------------------
from starlette.middleware.base import BaseHTTPMiddleware

# -----------------------------
# Internal Imports (App-specific)
# -----------------------------
from app.database import engine
from app import models
from app.user import router as user_router
from app.resource import router as resource_router
from app.admin import router as admin_router
from app.utils import log_event
from app.limiter_config import limiter

# -----------------------------
# Load environment variables from .env
# -----------------------------
load_dotenv()

# -----------------------------
# Create all tables defined in models
# -----------------------------
models.Base.metadata.create_all(bind=engine)

# -----------------------------
# Logger Configuration
# -----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("app.log"),   # Save logs to file
        logging.StreamHandler()           # Print logs to console
    ]
)

logger = logging.getLogger("app")

# -----------------------------
# Middleware to reject large requests
# -----------------------------
MAX_PAYLOAD_SIZE = 10240  # 10 KB payload limit

class PayloadLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        body = await request.body()
        if len(body) > MAX_PAYLOAD_SIZE:
            return JSONResponse(status_code=413, content={"detail": "Payload too large"})
        request._body = body
        return await call_next(request)

# -----------------------------
# Initialize FastAPI App
# -----------------------------
app = FastAPI()

# -----------------------------
# CORS Middleware: Allow all origins
# -----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # In production, restrict to specific domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Rate Limiting Handler (429 Error Response)
# -----------------------------
app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    lambda request, exc: JSONResponse(
        status_code=429,
        content={
            "error": "Too Many Requests",
            "message": "You have exceeded the limit of login attempts. Please try again later."
        }
    )
)

# -----------------------------
# Add SlowAPI and Custom Payload Middleware
# -----------------------------
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(PayloadLimitMiddleware)

# -----------------------------
# Register application Routers
# -----------------------------
app.include_router(user_router)
app.include_router(resource_router)
app.include_router(admin_router)

# -----------------------------
# Custom middleware for root redirect and logging
# -----------------------------
@app.middleware("http")
async def route_based_on_user_agent(request: Request, call_next):
    user_agent = request.headers.get("user-agent", "Unknown").lower()

    # If browser requests root URL, redirect to Swagger docs
    if request.url.path == "/" and "mozilla" in user_agent:
        return RedirectResponse(url="/docs")
    
    # Log request metadata
    ip = request.client.host
    ua = user_agent
    log_event("info", "HTTP REQUEST", f"{request.method} {request.url.path}", request)

    # Proceed to next middleware or route
    response = await call_next(request)
    return response

# -----------------------------
# Local Development Server Entrypoint
# -----------------------------
def run():
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)  # Hot-reload enabled for dev
