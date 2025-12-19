# Attestful Docker Image
#
# Multi-stage build optimized for offline/air-gapped deployment.
# Includes all dependencies baked in for zero network requirements.
#
# Build:
#   docker build -t attestful:latest -f docker/Dockerfile .
#
# Run:
#   docker run -it --rm -v ~/.attestful:/app/data attestful:latest scan aws
#
# Air-gapped usage:
#   docker save attestful:latest | gzip > attestful-image.tar.gz
#   docker load < attestful-image.tar.gz

# =============================================================================
# Stage 1: Builder
# =============================================================================
FROM python:3.11-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set up virtual environment
ENV VIRTUAL_ENV=/opt/venv
RUN python -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install pip tools
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy requirements first for caching
WORKDIR /build

# Copy pyproject.toml and poetry.lock for dependency resolution
COPY pyproject.toml poetry.lock* ./

# Install poetry and export requirements
RUN pip install --no-cache-dir poetry && \
    poetry config virtualenvs.create false && \
    poetry export -f requirements.txt --without-hashes -o requirements.txt || \
    echo "No poetry.lock, will install from pyproject.toml"

# Install dependencies
RUN if [ -f requirements.txt ]; then \
        pip install --no-cache-dir -r requirements.txt; \
    fi

# Copy source and install
COPY src/ ./src/
COPY README.md ./

# Install attestful
RUN pip install --no-cache-dir -e .

# =============================================================================
# Stage 2: OSCAL Data
# =============================================================================
FROM python:3.11-slim-bookworm AS oscal-data

WORKDIR /data

# Copy OSCAL catalogs and profiles
COPY data/oscal/ ./oscal/
COPY data/standards/ ./standards/

# =============================================================================
# Stage 3: Runtime
# =============================================================================
FROM python:3.11-slim-bookworm AS runtime

# Labels
LABEL org.opencontainers.image.title="Attestful"
LABEL org.opencontainers.image.description="OSCAL-first compliance automation platform"
LABEL org.opencontainers.image.source="https://github.com/clay-good/attestful"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV VIRTUAL_ENV=/opt/venv

# Copy OSCAL data
COPY --from=oscal-data /data /app/data

# Set up app directory
WORKDIR /app

# Create non-root user
RUN useradd --create-home --shell /bin/bash attestful && \
    chown -R attestful:attestful /app

# Create data directories
RUN mkdir -p /app/data/evidence /app/data/reports /app/config && \
    chown -R attestful:attestful /app

# Copy application source
COPY --from=builder /build/src ./src/

# Environment configuration
ENV ATTESTFUL_DATA_DIR=/app/data
ENV ATTESTFUL_CONFIG_DIR=/app/config
ENV ATTESTFUL_OFFLINE_MODE=true
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Switch to non-root user
USER attestful

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD attestful --version || exit 1

# Default entrypoint
ENTRYPOINT ["attestful"]
CMD ["--help"]

# =============================================================================
# Stage 4: Development (optional, for dev builds)
# =============================================================================
FROM runtime AS development

USER root

# Install dev tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    vim \
    less \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install dev dependencies
RUN pip install --no-cache-dir \
    pytest \
    pytest-cov \
    ipython \
    rich

USER attestful

CMD ["bash"]
