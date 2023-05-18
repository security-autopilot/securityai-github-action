FROM python:3.9-slim

# Set the environment variables in the Docker container
ENV GITHUB_TOKEN=$GITHUB_TOKEN
ENV REPO_NAME=$REPO_NAME
ENV BASE_URL=$BASE_URL
ENV PR_NUMBER=$PR_NUMBER
ENV THRESHOLD=$THRESHOLD

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY scan_and_fix.py /app/scan_and_fix.py

ENTRYPOINT ["python", "/app/scan_and_fix.py"]
