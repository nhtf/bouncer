FROM alpine:latest

run addgroup bouncer && adduser -HDG bouncer bouncer -s /sbin/nologin

RUN set -x \
	&& apk update \
	&& apk upgrade \
	&& apk add rust

RUN set -ex; \
	mkdir -p /var/run/bouncerd; \
	chown -R bouncer:bouncer /var/run/bouncerd;

WORKDIR /var/run/bouncerd
COPY . .

EXPOSE 8080
USER bouncer

RUN cargo build -r
