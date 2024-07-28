FROM golang:1.20
WORKDIR /app
COPY ./client/src ./client/src
COPY ./client/certs ./client/certs
COPY ./client/static ./client/static
COPY ./client/templates ./client/templates
WORKDIR /app/client/src
RUN go mod download
RUN go build -o main .
EXPOSE ${PORT}
CMD ["./main"]