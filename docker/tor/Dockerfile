FROM alpine:3.20
RUN apk add --no-cache tor \
 && mkdir -p /var/lib/tor && chown tor:tor /var/lib/tor && chmod 700 /var/lib/tor
COPY torrc.base /etc/tor/torrc.base
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
USER tor
ENTRYPOINT ["/entrypoint.sh"]
