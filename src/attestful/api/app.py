"""
Main FastAPI application for Attestful REST API.
"""

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse

    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    FastAPI = None  # type: ignore[misc, assignment]
    CORSMiddleware = None  # type: ignore[misc, assignment]
    JSONResponse = None  # type: ignore[misc, assignment]

from attestful import __version__
from attestful.core.logging import get_logger

if TYPE_CHECKING:
    from fastapi import FastAPI as FastAPIType

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: "FastAPIType"):
    """
    Lifespan context manager for FastAPI app.
    Handles startup and shutdown events.
    """
    # Startup
    logger.info("Starting Attestful API server")
    # Database initialization would go here
    logger.info("API server started")

    yield

    # Shutdown
    logger.info("Shutting down Attestful API server")


def create_api_app() -> "FastAPIType | None":
    """
    Create and configure the FastAPI application.

    Returns:
        FastAPI app instance or None if FastAPI is not available
    """
    if not FASTAPI_AVAILABLE:
        logger.error("FastAPI is not installed. Install with: pip install 'attestful[enterprise]'")
        return None

    # Create FastAPI app
    app = FastAPI(
        title="Attestful API",
        description="REST API for OSCAL-first compliance automation platform",
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately in production
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-API-Key", "Authorization"],
    )

    # Health check endpoint
    @app.get("/health", tags=["Health"])
    async def health_check():
        """Health check endpoint."""
        return {"status": "healthy", "version": __version__}

    # API info endpoint
    @app.get("/api/v1/info", tags=["Info"])
    async def api_info():
        """Get API information."""
        return {
            "name": "Attestful API",
            "version": __version__,
            "description": "OSCAL-first compliance automation platform",
            "frameworks": [
                "NIST CSF 2.0",
                "NIST 800-53",
                "FedRAMP",
                "SOC 2",
                "ISO 27001",
                "HITRUST",
            ],
        }

    # Global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc):  # noqa: ARG001
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal server error",
                "message": str(exc),
            },
        )

    logger.info(
        "API application created",
        version=__version__,
    )

    return app


def run_api_server(host: str = "0.0.0.0", port: int = 8000, reload: bool = False) -> None:  # noqa: S104
    """
    Run the API server using uvicorn.

    Args:
        host: Host to bind to
        port: Port to run on
        reload: Enable auto-reload for development
    """
    if not FASTAPI_AVAILABLE:
        logger.error("FastAPI is not installed. Install with: pip install 'attestful[enterprise]'")
        return

    try:
        import uvicorn
    except ImportError:
        logger.error("Uvicorn is not installed. Install with: pip install 'attestful[enterprise]'")
        return

    logger.info(f"Starting API server on http://{host}:{port}")
    logger.info(f"API documentation available at http://{host}:{port}/docs")

    try:
        uvicorn.run(
            "attestful.api.app:create_api_app",
            host=host,
            port=port,
            reload=reload,
            factory=True,
        )
    except Exception as e:
        logger.error(f"Failed to start API server: {e}")
        raise
