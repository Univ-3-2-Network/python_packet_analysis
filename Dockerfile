FROM python:3.11-slim

# Build arguments from .env file
ARG SSH_ROOT_PASSWORD=password

# Install system dependencies required for scapy and network operations
RUN apt-get update && apt-get install -y \
    gcc \
    libpcap-dev \
    tcpdump \
    iproute2 \
    net-tools \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH with password from build arg
RUN mkdir -p /var/run/sshd && \
    echo "root:${SSH_ROOT_PASSWORD}" | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Set working directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY ./app/requirements.txt /app/requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Use volume for application code (mount ./app at runtime)
VOLUME ["/app"]

# Run as non-root user for security (optional, uncomment if needed)
# RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
# USER appuser

# Expose SSH port
EXPOSE 22

# Start SSH service and Python application
CMD service ssh start && python
# python app.py