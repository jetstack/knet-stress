FROM alpine:3.11

LABEL maintainers="joshvanl"
LABEL description="A Kubernetes network stress test introspective tool"

RUN apk --no-cache add curl

COPY ./bin/knet-stress /knet-stress

ENTRYPOINT ["/knet-stress"]
