FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y netcat-openbsd

# Mirror ex1 behavior: ensure a requirements file is present in the image
# ex2 uses external-requirements.txt, so copy it as requirements.txt
COPY src/external-requirements.txt requirements.txt

COPY src .

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
