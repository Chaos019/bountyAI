# Use a lightweight Python image
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies
COPY ./bountyai/server/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the source code
COPY ./bountyai ./bountyai

# Expose the FastAPI port
EXPOSE 8000

# Run the application with Uvicorn
CMD ["uvicorn", "bountyai.server.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
