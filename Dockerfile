# Use Python 3 as the base image
FROM python:3.10

# Set the working directory in the container
WORKDIR /app

# Copy requirements.txt into the container
COPY requirements.txt /app

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the rest of the application files into the container
COPY . /app

# Expose the necessary ports
EXPOSE 5001
EXPOSE 5002

# Define a volume for persistent configs in /app/config
VOLUME ["/app/config"]
VOLUME ["/app/logs"]

# Specify the command to run when the container starts
CMD ["python", "-u", "tnc.py"]
