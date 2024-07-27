FROM golang:1.20
WORKDIR /app
COPY ./src ./src
COPY ./certs ./certs
COPY ./static ./static
COPY ./templates ./templates
WORKDIR /app/src
RUN go mod download
RUN go build -o main .
EXPOSE ${PORT}
CMD ["./main"]