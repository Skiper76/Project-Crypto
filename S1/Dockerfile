FROM python:3.8-slim
WORKDIR /app
RUN pip install --no-cache-dir flask bcrypt requests
COPY . .
EXPOSE 5000
CMD ["python", "app.py"]
