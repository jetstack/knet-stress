FROM alpine:3.11

LABEL description="A Kubernetes network stress test introspective tool"

COPY ./bin/knet-stress /knet-stress

ENTRYPOINT ["/knet-stress"]
