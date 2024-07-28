FROM golang:1.20
WORKDIR /app
COPY ./notes ./notes
COPY ./notes/certs ./notes/certs
WORKDIR /app/notes
RUN go mod download
RUN go build -o main .
EXPOSE ${PORT}
EXPOSE ${POSTGRES_PORT}
CMD ["./main"]