#!/bin/bash

MAILGW_IMAGE=$(cat .env |grep ^MAILGW_IMAGE|cut -d"=" -f2|tail -n1)
[[ -z "$MAILGW_IMAGE" ]] && MAILGW_IMAGE=ghcr.io/globalsecurityagency/tor-imap-smtp-gateway-cluster

MULTITOR_IMAGE=$(cat .env |grep ^MULTITOR_IMAGE|cut -d"=" -f2|tail -n1)
[[ -z "$MULTITOR_IMAGE" ]] && MULTITOR_IMAGE=ghcr.io/globalsecurityagency/torgw

#echo RUN ON YOUR CLIENTS:"$MULTITOR_IMAGE:latest;docker tag 254.254.254.254:5001/multitor-nodejs:latest multitor-nodejs;docker pull $MAILGW_IMAGE;docker tag $MAILGW_IMAGE mailviaonion:latest"
echo RUN ON YOUR CLIENTS:"$MULTITOR_IMAGE:latest;docker tag 254.254.254.254:5001/multitor-nodejs:latest multitor-nodejs;docker pull $MAILGW_IMAGE;docker tag $MAILGW_IMAGE mailviaonion:latest"