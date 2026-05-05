FROM python:3.11-slim

# Upgrade OS packages to patch vulnerabilities (e.g. glibc)
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /soc

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip wheel
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install gunicorn eventlet

# Copy application files
COPY backend/ backend/

# Set working directory to backend
WORKDIR /soc/backend

# Expose API port
EXPOSE 5000

# Start server using Gunicorn and Eventlet for WebSockets
CMD ["gunicorn", "-k", "eventlet", "-w", "1", "-b", "0.0.0.0:5000", "app:app"]
