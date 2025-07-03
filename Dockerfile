# Dockerfile for AegisLens

# Start with a lightweight Python base image.
# Using python:3.12-slim to match our development environment for maximum stability.
FROM python:3.12-slim

# Set the working directory inside the container.
WORKDIR /app

# Copy the dependencies file first to leverage Docker's layer caching.
# This layer will only be rebuilt if requirements.txt changes.
COPY requirements.txt /app/requirements.txt

# Install the Python dependencies.
# --no-cache-dir ensures that pip does not store the wheel cache, reducing image size.
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the working directory.
# This includes app.py, models/, styles/, and all other necessary files.
COPY . /app

# Expose port 8000 to allow traffic to the Streamlit application.
EXPOSE 8000

# Define the command to run when the container starts.
# This runs the Streamlit application and binds it to all network interfaces
# on port 8000, which is necessary for it to be accessible from outside the container.
CMD ["streamlit", "run", "app.py", "--server.port=8000", "--server.address=0.0.0.0"]
