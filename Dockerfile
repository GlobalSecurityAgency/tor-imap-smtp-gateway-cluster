#FROM alpine
#RUN /bin/ash -c "apk add gcc automake autoconf git build-base readline-dev linux-headers openssl-dev;git clone https://github.com/runsisi/socat.git;cd socat;autoreconf -i;./configure ;make -j3 socat;cp socat /usr/bin;apk del gcc automake git build-base linux-headers openssl-dev automake autoconf"
#FROM golang:1.17-alpine
FROM alpine
RUN apk add socat bash perdition  openssl curl avahi avahi-tools dbus dnsmasq
RUN wget -c "https://gitlab.com/the-foundation/avahi-browse-to-hostfile/-/raw/master/avahi-to-hosts.sh?inline=false" -O /avahi-to-hosts.sh
#PORT=11143;TORGW=192.168.1.1;apk add perdition torsocks openssl socat curl tor screen;test -e /etc/perdition/perdition.crt.pem || (cd /etc/perdition/; ( ( echo;echo;echo;echo;echo;echo;echo;echo;echo;echo;echo;echo) | openssl req -new -x509 -nodes -out perdition.crt.pem -keyout perdition.key.pem -newkey rsa:4096 -days 3650 );test -e dhparams.pem || openssl dhparam -out dhparams.pem -dsaparam 4096 ; mkdir  -p /usr/var/run/perdition.imap4s ; cat dhparams.pem >> /etc/perdition/perdition.crt.pem ); screen -dmS perditionsocat socat TCP-LISTEN:$PORT,bind=$(ip a |grep global|grep -v inet6|cut -d"/" -f1|cut -dt -f2 |sed "s/ //g" ),fork,reuseaddr TCP-CONNECT:127.0.0.1:$PORT;screen -dmS torsocat socat TCP-LISTEN:9050,fork,reuseaddr TCP-CONNECT:$TORGW:9050;touch /tmp/null; perdition.imap4s --no_daemon --protocol IMAP4S -f /tmp/null  --outgoing_server 192.168.26.242 --outgoing_port 143 --explicit_domain eb.be.eu.org  --listen_port $PORT --bind_address=127.0.0.1:$PORT -F '+'  --pid_file /tmp/perdition.pid --ssl_no_cert_verify --ssl_no_client_cert_verify --ssl_no_cn_verify        --tcp_keepalive 

#RUN uname -a |grep aarch64 || go get -u -v github.com/wzshiming/bridge/cmd/bridge
RUN uname -a |grep -e 386 || (wget -c https://github.com/wzshiming/bridge/releases/download/v0.8.9/bridge_linux_386 -O /bridge)
RUN uname -a |grep -e armv6 -e armhf -e armv7l || (wget -c https://github.com/wzshiming/bridge/releases/download/v0.8.9/bridge_linux_arm -O /bridge)
RUN uname -a |grep -e amd64 -e x86_64 || (wget -c https://github.com/wzshiming/bridge/releases/download/v0.8.9/bridge_linux_amd64 -O /bridge)
RUN uname -a |grep aarch64 && (wget -c https://github.com/wzshiming/bridge/releases/download/v0.8.9/bridge_linux_arm64 -O /bridge)

RUN chmod +x /bridge
EXPOSE 25 587 465 110 995 143 993
COPY tormail_subdomains.sh /

#RUN chmod +x /tormail_subdomains.sh
#RUN cat /tormail_subdomains.sh
