FROM python:3.13-slim

WORKDIR /app
RUN pip install --no-cache-dir pipenv
COPY app/Pipfile .
COPY app/Pipfile.lock .
RUN pipenv install --system --deploy
COPY app .

RUN python -m grpc_tools.protoc \
    -I./grpc \
    --pyi_out=python-server \
    --python_out=python-server \
    --grpc_python_out=python-server \
    ./grpc/tls13.proto

EXPOSE 50051

CMD ["python", "python-server/server.py"]
