FROM alpine:latest

RUN addgroup bouncer && adduser -HDG bouncer bouncer -s /sbin/nologin

RUN set -x \
	&& apk update \
	&& apk upgrade \
	&& apk add openssl-dev pkgconf rust cargo

COPY . /tmp/bouncer
WORKDIR /tmp/bouncer
RUN cargo install --path . --root /

RUN set -x \
	&& apk del openssl-dev pkgconf cargo \
	&& apk update \
	&& apk upgrade \
	&& apk add openssl

EXPOSE 8080
USER bouncer
ENTRYPOINT ["bouncer"]
