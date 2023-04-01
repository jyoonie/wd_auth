### base image

FROM golang:1.19-alpine AS builder
WORKDIR /source
COPY . .

RUN go mod download
RUN go build cmd/main.go

### production image

FROM alpine:latest 
WORKDIR /root/
COPY --from=builder /source/main .

ENV WDIET_SERVICE_PORT=8081

ENV WDIET_DB_HOST=wdiet_db
ENV WDIET_DB_PORT=5432
ENV WDIET_DB_USER=postgres
ENV WDIET_DB_PASS=secret
ENV WDIET_DB_NAME=postgres

CMD [ "./main" ]