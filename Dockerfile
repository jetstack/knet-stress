#FROM alpine:3.11
FROM ubuntu

LABEL description="A Kubernetes network stress test introspective tool"

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y curl iproute2 iputils-ping

COPY ./bin/knet-stress /knet-stress

ENTRYPOINT ["/knet-stress"]
