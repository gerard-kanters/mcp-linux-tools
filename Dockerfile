FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /opt/mcp

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /opt/mcp/sandbox

EXPOSE 8765

CMD ["python", "server.py"]
