FROM alpine:latest

run addgroup bouncer && adduser -HDG bouncer bouncer -s /sbin/nologin

RUN set -x \
	&& apk update \
	&& apk upgrade \
	&& apk add openssl-dev pkgconf rust cargo

COPY . /tmp/bouncer
WORKDIR /tmp/bouncer
RUN cargo install --path . --root /

EXPOSE 8080
USER bouncer
ENTRYPOINT ["bouncer"]
