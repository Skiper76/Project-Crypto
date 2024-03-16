FROM python:3.8
WORKDIR /app
RUN pip install --no-cache-dir flask tink
COPY . .
COPY cert.pem /app/cert.pem
COPY key.pem /app/key.pem
EXPOSE 8081
CMD ["python", "hsm.py"]
