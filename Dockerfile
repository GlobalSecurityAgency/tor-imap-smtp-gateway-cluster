#FROM alpine
#RUN /bin/ash -c "apk add gcc automake autoconf git build-base readline-dev linux-headers openssl-dev;git clone https://github.com/runsisi/socat.git;cd socat;autoreconf -i;./configure ;make -j3 socat;cp socat /usr/bin;apk del gcc automake git build-base linux-headers openssl-dev automake autoconf"
#FROM golang:1.17-alpine
FROM alpine
#RUN apk add --no-cache wget 

RUN (uname -a |grep -e 386 && (wget -c https://github.com/wzshiming/bridge/releases/download/v0.11.1/bridge_linux_386 -O /bridge) ) || true 
RUN (uname -a |grep -e armv6 -e armhf -e armv7l && (wget -c https://github.com/wzshiming/bridge/releases/download/v0.11.1/bridge_linux_arm -O /bridge)  ) || true 
RUN (uname -a |grep -e amd64 -e x86_64 && (wget -c https://github.com/wzshiming/bridge/releases/download/v0.11.1/bridge_linux_amd64 -O /bridge)  ) || true 
RUN (uname -a |grep aarch64 && (wget -c https://github.com/wzshiming/bridge/releases/download/v0.11.1/bridge_linux_arm64 -O /bridge) ) || true 

RUN apk add --no-cache socat bash perdition  openssl curl avahi avahi-tools dbus dnsmasq  nginx nginx-mod-stream
RUN wget -c "https://gitlab.com/the-foundation/avahi-browse-to-hostfile/-/raw/master/avahi-to-hosts.sh?inline=false" -O /avahi-to-hosts.sh
RUN grep avahi_tohosts /avahi-to-hosts.sh

#RUN uname -a |grep aarch64 || go get -u -v github.com/wzshiming/bridge/cmd/bridge

RUN chmod +x /bridge
EXPOSE 25 587 465 110 995 143 993
COPY tormail_subdomains.sh /

#RUN chmod +x /tormail_subdomains.sh
#RUN cat /tormail_subdomains.sh
