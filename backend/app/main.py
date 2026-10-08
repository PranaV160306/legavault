from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from .config import settings, BASE_DIR
from .database import engine, Base
from .routers import auth, documents, audit, users

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure database tables exist
    Base.metadata.create_all(bind=engine)
    settings.VAULT_DIR.mkdir(parents=True, exist_ok=True)
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Objective 1: Secure Role-Based Document Transfer System with AES-256-GCM, RBAC, OTP, and Audit Logs",
    lifespan=lifespan
)

# Enable CORS for React frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routers under both /api and root paths for convenience
for prefix in ["/api", ""]:
    app.include_router(auth.router, prefix=prefix)
    app.include_router(documents.router, prefix=prefix)
    app.include_router(audit.router, prefix=prefix)
    app.include_router(users.router, prefix=prefix)

@app.get("/health")
@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "LegaVault Objective 1 Security Engine",
        "encryption": "AES-256-GCM",
        "otp_mode": "DEVELOPMENT" if settings.OTP_DEV_MODE else "PRODUCTION",
        "vault_path": str(settings.VAULT_DIR)
    }

@app.get("/")
def root():
    return {
        "message": "Welcome to LegaVault Objective 1 Secure Document API",
        "docs": "/docs",
        "health": "/api/health",
        "web_app": "/app"
    }

# Mount static build of React frontend if present
dist_path = BASE_DIR.parent / "frontend" / "dist"
if dist_path.exists():
    from fastapi.staticfiles import StaticFiles
    app.mount("/app", StaticFiles(directory=dist_path, html=True), name="frontend_app")
