FROM alpine:3.14

RUN apk update
RUN apk add vim
RUN apk add curl
