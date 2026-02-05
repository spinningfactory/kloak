FROM python:3.11-slim

WORKDIR /app

# Install requests
RUN pip install --no-cache-dir requests

# Copy application
COPY app.py .

# Run the demo
CMD ["python", "-u", "app.py"]
