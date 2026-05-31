FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    g++ \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy entire project
COPY . .

# Create necessary directories
RUN mkdir -p logs models data brain/models

# Expose port for dashboard
EXPOSE 5000

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV NEURAL_SOAR_HOME=/app

# Default command runs simulation
CMD ["python", "scripts/run_simulation.py", "--mode", "simulate"]
