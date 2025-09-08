FROM python:3.10-slim

RUN apt-get update && apt-get install -y ffmpeg wget

# This ensures the yt-dlp command is installed and available
RUN wget https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp -O /usr/local/bin/yt-dlp
RUN chmod a+rx /usr/local/bin/yt-dlp

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# This copies your new, valid cookies file into the server
COPY cookies.txt /app/cookies.txt

COPY . .

EXPOSE 8000

# *** THE TYPO IS FIXED HERE ***
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]


