"""
IDS Backend - Main Application Entry Point

This is the FastAPI application that serves as the Network Intrusion
Detection System (IDS) backend. It provides REST API endpoints for
managing signatures, viewing alerts, and controlling the detection engine.

Usage:
    Development: uvicorn app.main:app --reload
    Production:  uvicorn app.main:app --host 0.0.0.0 --port 8000

Note: Packet capture requires root privileges or CAP_NET_RAW capability.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import settings
from app.core.logging import ids_logger
from app.database.init_db import init_database
from app.api.deps import init_detection_engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.

    Handles startup and shutdown events:
    - Startup: Initialize database, load signatures
    - Shutdown: Stop detection engine gracefully
    """
    # Startup
    ids_logger.info("=" * 60)
    ids_logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    ids_logger.info("=" * 60)

    # Initialize database tables
    ids_logger.info("Initializing database...")
    init_database()

    # Initialise detection engine (don't start automatically - use API)
    detector = init_detection_engine()
    ids_logger.info("Detection engine ready (not started)")
    ids_logger.info(f"Configured interface: {settings.NETWORK_INTERFACE}")

    ids_logger.info("Application startup complete")
    ids_logger.info(f"API available at: http://localhost:8000{settings.API_PREFIX}")
    ids_logger.info("API docs at: http://localhost:8000/docs")

    yield  # Application runs here

    # Shutdown
    ids_logger.info("Shutting down application...")

    # Stop detection if running
    if detector.is_running:
        ids_logger.info("Stopping detection engine...")
        detector.stop_detection()

    ids_logger.info("Application shutdown complete")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    description="""
    ## Network Intrusion Detection System (IDS) Backend
    
    A signature-based IDS for small-scale business networks.
    
    ### Features:
    - **Packet Capture**: Sniff network traffic using Scapy
    - **Signature Matching**: Detect threats using regex and header patterns
    - **Alert Management**: View, filter, and manage security alerts
    - **REST API**: Full control via HTTP endpoints
    
    ### Quick Start:
    1. Start the API server
    2. Load signatures via POST /api/v1/system/signatures/reload
    3. Start detection via POST /api/v1/system/detection/start
    4. View alerts via GET /api/v1/alerts
    
    **Note**: Packet capture requires root/admin privileges.
    """,
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_HOSTS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API router
app.include_router(api_router, prefix=settings.API_PREFIX)


@app.get("/", tags=["Root"])
def root():
    """
    Root endpoint - basic application info.

    Returns application name, version, and links to documentation.
    """
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
        "docs": "/docs",
        "api": settings.API_PREFIX,
    }


@app.get("/ping", tags=["Root"])
def ping():
    """
    Simple ping endpoint for health monitoring.

    Returns 'pong' to confirm the service is responsive.
    """
    return {"ping": "pong"}


# Allow running directly with: python -m app.main
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
    )
