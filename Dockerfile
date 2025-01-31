# Use Python 3 as the base image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy requirements.txt into the container
COPY requirements.txt /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        libyaml-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install --upgrade pip setuptools wheel
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the rest of the application files into the container
COPY tnc.py /app

# Expose the necessary ports
EXPOSE 5001
EXPOSE 5002

# Define a volume for persistent configs in /app/config
VOLUME ["/app/config"]
VOLUME ["/app/logs"]

# Specify the command to run when the container starts
CMD ["python", "-u", "tnc.py"]
