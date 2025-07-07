FROM ubuntu:22.04@sha256:b6b83d3c331794420340093eb706a6f152d9c1fa51b262d9bf34594887c2c7ac

RUN apt-get update && \
    apt-get install -y socat && \
    apt-get clean

WORKDIR /home/ctf
COPY shellphobia /home/ctf/
COPY flag /home/ctf/

RUN chmod +x /home/ctf/shellphobia

RUN useradd -m ctf && \
    chown -R root:ctf /home/ctf && \
    chmod 750 /home/ctf && \
    chmod 740 /home/ctf/flag

EXPOSE 1337

CMD ["socat", "tcp-listen:1337,reuseaddr,fork", "EXEC:/home/ctf/shellphobia,stderr,su=ctf"]
