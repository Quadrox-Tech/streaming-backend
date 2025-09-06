# 1. Start with an official Python base image
FROM python:3.10-slim

# Add this line to install FFmpeg
RUN apt-get update && apt-get install -y ffmpeg

# 2. Set the working directory inside the container
WORKDIR /app

# 3. Copy the dependencies file into the container
COPY requirements.txt .

# 4. Install the dependencies
RUN pip install --no-cache-dir -r requirements.txt

# 5. Copy the rest of your application code into the container
COPY . .

# 6. Tell the container that the app will listen on port 8000
EXPOSE 8000

# 7. Define the command to run your app using gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]
