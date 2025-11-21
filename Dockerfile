# Use the official Python lightweight image
FROM python:3.13-slim

# Install the project into /app
COPY . /app
WORKDIR /app

# Allow statements and log messages to immediately appear in the logs
ENV PYTHONUNBUFFERED=1

# Install dependencies

RUN pip install -r requirements.txt

EXPOSE $PORT

# Run the FastMCP server
CMD ["python3", "-m", "src.server"]