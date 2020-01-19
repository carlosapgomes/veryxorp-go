# Start by building the application.
FROM golang:1.13-buster as build

WORKDIR /go/src/app
ADD . /go/src/app
RUN go get -d -v ./...


RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /go/bin/app/veryxorp main.go

EXPOSE 80
EXPOSE 443
# Now copy it into our base image.
FROM gcr.io/distroless/base-debian10
COPY --from=build /go/bin/app/veryxorp /
CMD ["/veryxorp"]
