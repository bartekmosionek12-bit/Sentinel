# Host demo-lab do skanu uwierzytelnionego (172.30.99.16). Ufa wyłącznie certyfikatom
# podpisanym przez CA z OpenBao (TrustedUserCAKeys), bez haseł i bez kluczy w authorized_keys.
FROM alpine:3.22
RUN apk add --no-cache openssh-server \
    && adduser -D -s /bin/sh sentinel-scan \
    && sed -i 's/^sentinel-scan:!/sentinel-scan:*/' /etc/shadow \
    && mkdir -p /etc/ssh/principals \
    && echo sentinel-scan > /etc/ssh/principals/sentinel-scan
COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
