# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Create the config directory if it doesn't exist
RUN mkdir -p config

# Expose the port the app runs on (matching your server.py)
EXPOSE 50100

# Run the application
CMD ["python", "server.py"]