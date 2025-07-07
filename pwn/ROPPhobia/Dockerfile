FROM ubuntu@sha256:152dc042452c496007f07ca9127571cb9c29697f42acbfad72324b2bb2e43c98

RUN apt update && apt install -y socat

RUN mkdir /app
WORKDIR /app

COPY flag /
COPY chal /app/
COPY flag /app/

RUN chmod +x /app/chal

EXPOSE 1337

CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"/app/chal"