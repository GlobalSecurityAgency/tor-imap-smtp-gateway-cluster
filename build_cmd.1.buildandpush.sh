#!/bin/bash

MAILGW_IMAGE=$(cat .env |grep ^MAILGW_IMAGE|cut -d"=" -f2|tail -n1)
[[ -z "$MAILGW_IMAGE" ]] && MAILGW_IMAGE=ghcr.io/globalsecurityagency/tor-imap-smtp-gateway-cluster

MULTITOR_IMAGE=$(cat .env |grep ^MULTITOR_IMAGE|cut -d"=" -f2|tail -n1)
[[ -z "$MULTITOR_IMAGE" ]] && MULTITOR_IMAGE=ghcr.io/globalsecurityagency/torgw

echo "$MULTITOR_IMAGE" |grep -q ghcr.io/globalsecurityagency/torgw || docker pull ghcr.io/globalsecurityagency/torgw &
echo $MAILGW_IMAGE     |grep -q ghcr.io/globalsecurityagency/tor-imap-smtp-gateway-cluster || docker pull ghcr.io/globalsecurityagency/tor-imap-smtp-gateway-cluster & 
wait

#docker build -t ghcr.io/globalsecurityagency/multitor-nodejs:latest  multitor-nodejs
#docker push ghcr.io/globalsecurityagency/multitor-nodejs:latest|grep -v -e "Preparing" -e "already exists" &

test -e multitor-torgw || git clone  https://github.com/GlobalSecurityAgency/torgw.git multitor-torgw
docker build -t $MULTITOR_IMAGE:latest  multitor-torgw
docker push $MULTITOR_IMAGE:latest|grep -v -e "Preparing" -e "already exists" &

docker build -t $MAILGW_IMAGE . ;
docker push $MAILGW_IMAGE   |grep -v -e "Preparing" -e "already exists" &

wait;
echo "NOW PULL AND DEPLOY"

#docker pull ghcr.io/y0l0-os/tor-load-balancer-docker:main;
#docker tag ghcr.io/y0l0-os/tor-load-balancer-docker:main ghcr.io/globalsecurityagency/tor-load-balancer-docker;
#docker push ghcr.io/globalsecurityagency/tor-load-balancer-docker

