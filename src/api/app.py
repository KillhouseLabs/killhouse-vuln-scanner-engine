"""FastAPI application for scanner engine"""

import logging
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
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routes
app.include_router(router)
