FROM alpine:3.19.1

RUN apk add --no-cache python3 py3-pip py3-kubernetes py3-redis redis bind-tools

COPY ./redis-labeler.py .

ENTRYPOINT [ "python3" ]

CMD ["./redis-labeler.py"]
