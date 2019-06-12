FROM golang:1.12-alpine AS development

ENV PROJECT_PATH=/lora-app-server
ENV PATH=$PATH:$PROJECT_PATH/build
ENV GO_EXTRA_BUILD_ARGS="-a -installsuffix cgo"

RUN apk add --no-cache ca-certificates make git bash protobuf alpine-sdk nodejs nodejs-npm python3 openssl-dev openssl py-pip gcc linux-headers make python-dev
RUN pip install grpcio grpcio-tools
RUN mkdir -p $PROJECT_PATH
COPY . $PROJECT_PATH
WORKDIR $PROJECT_PATH

RUN make dev-requirements ui-requirements
RUN make

FROM alpine:latest AS production

WORKDIR /root/
RUN apk --no-cache add ca-certificates
COPY --from=development /lora-app-server/build/lora-app-server .
ENTRYPOINT ["./lora-app-server"]
