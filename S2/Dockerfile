FROM python:3.8
WORKDIR /app
RUN pip install --no-cache-dir flask tink
COPY . .
EXPOSE 8081
CMD ["python", "hsm.py"]
