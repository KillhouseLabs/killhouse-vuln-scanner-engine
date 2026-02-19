"""FastAPI application for scanner engine"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routes import router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger("killhouse-scanner")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for application startup and shutdown

    Args:
        app: FastAPI application instance
    """
    logger.info("Scanner engine started")
    yield
    logger.info("Scanner engine stopped")


app = FastAPI(
    title="Killhouse Scanner Engine",
    version="1.0.0",
    description="Vulnerability scanner engine API",
    lifespan=lifespan,
)

# Add CORS middleware
ALLOWED_ORIGINS = os.environ.get(
    "CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:3001"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Scanner-API-Key"],
)

# Include routes
app.include_router(router)
