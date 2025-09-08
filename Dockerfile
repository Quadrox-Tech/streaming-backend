# 1. Start with an official Python base image
FROM python:3.10-slim

# 2. Install FFmpeg
RUN apt-get update && apt-get install -y ffmpeg wget

# 3. *** THE FIX ***
# Download the latest yt-dlp binary directly and make it executable.
# This is more reliable than relying on the pip package's command-line script.
RUN wget https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp -O /usr/local/bin/yt-dlp
RUN chmod a+rx /usr/local/bin/yt-dlp

# 4. Set the working directory inside the container
WORKDIR /app

# 5. Copy the dependencies file into the container
COPY requirements.txt .

# 6. Install the Python package dependencies
RUN pip install --no-cache-dir -r requirements.txt

# 7. Copy the rest of your application code into the container
COPY . .

# 8. Tell the container that the app will listen on port 8000
EXPOSE 8000

# 9. Define the command to run your app using gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]

