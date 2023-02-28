#!/bin/bash
#echo nameserver 8.8.8.8 > /etc/resolv.conf
#echo nameserver 1.1.1.1 > /etc/resolv.conf
PREFIX=$1;


## use smtp and imap subdomains if they exist

IMAPTARGET=$2
testme=imap.$2
foundit=no
( for nameserver in 127.0.0.11 1.1.1.1 4.2.2.4 8.8.8.8 ;do (nslookup -type=A $testme  $nameserver |tail -n+3;nslookup -type=AAAA $testme $nameserver |tail -n+3) ;done  |grep ^Address  ) && foundit=yes
echo "$foundit"|grep -q yes && IMAPTARGET=imap.$2;

SMTPTARGET=$2;
testme=smtp.$2
foundit=no
( for nameserver in 127.0.0.11 1.1.1.1 4.2.2.4 8.8.8.8 ;do (nslookup -type=A $testme  $nameserver |tail -n+3;nslookup -type=AAAA $testme $nameserver |tail -n+3) ;done  |grep ^Address  ) && foundit=yes
echo "$foundit"|grep -q yes && SMTPTARGET=smtp.$2;


TORHOST=$3

[[ -z "$TORHOST" ]] && TORHOST=tor.local

#ip a |grep global|grep -v inet6|cut -d"/" -f1|cut -dt -f2 |sed "s/ //g" 
myip=$(ip a |grep global|grep -v inet6|cut -d"/" -f1|cut -dt -f2 |sed "s/ //g" )
echo "START: PREFIX=$1; IMAPTARGET=imap.$2; SMTPTARGET=smtp.$2; TORHOST=$3 LISTEN=$myip"

echo '[server]
use-ipv4=yes
use-ipv6=yes
enable-dbus=yes
ratelimit-interval-usec=1000000
ratelimit-burst=1000

[wide-area]
enable-wide-area=yes

[publish]
publish-hinfo=no
publish-workstation=no
publish-addresses=no


[reflector]

[rlimits]' > /etc/avahi/avahi-daemon.conf

dbus-daemon --nofork --config-file=/usr/share/dbus-1/system.conf  2>&1 |sed 's/^/  DBUS:/g' &
sleep 5
avahi-daemon -f /etc/avahi/avahi-daemon.conf  2>&1 |sed 's/^/AVAHI:/g' &

bash /avahi-to-hosts.sh --repeat   &
dnsmasq  -f -d --strict-order --no-resolv  --server "127.0.0.11#53" --addn-hosts=/etc/hosts.mdns 2>&1 |sed 's/^/DNSMQ:/g'  &
echo nameserver 127.0.0.1 > /etc/resolv.conf
## end bootstrap

sleepint=2

echo "NO" > /dev/shm/READY

[[ -z "$TORHOST" ]] || ( nslookup "$TORHOST" 127.0.0.11 &&  ping -c3 "$TORHOST" &&  ( echo "YES" >  /dev/shm/READY ))

grep -q "$TORHOST" /etc/hosts.mdns 2>/dev/null|wc -l  |grep ^0$ || ( echo "YES" >   /dev/shm/READY)

while (cat /dev/shm/READY 2>/dev/null |grep ^YES$ |wc -l |grep ^0$ );do
echo "NO AVAHI HOSTS DISCOVERED ..waiting $sleepint s"
echo "CURRENT AVAHI HOSTS:"$(cut -d" " -f1 /etc/hosts.mdns 2>/dev/null)

sleepint=$(($sleepint*2))
[[ -z "$sleepint" ]] && sleepint=2
sleep $sleepint
[[  $sleepint -gt 128 ]] && sleepint=4
grep -q "$TORHOST" /etc/hosts.mdns 2>/dev/null|wc -l  |grep ^0$ || ( echo "YES" >   /dev/shm/READY)
[[ -z "$TORHOST" ]] || ( nslookup "$TORHOST" 127.0.0.11 &&  ping -c3 "$TORHOST" &&  ( echo "YES" >  /dev/shm/READY ))
done

####

for  rport in 025:587 587:587 465:465;do 
  ( while (true) ;do   /bridge -b :${rport/:*/} -p $SMTPTARGET:${rport/*:/} -p socks5://$TORHOST:9050 2>&1 |grep -v -e '"remote_address": "127.0.0.1:' -e 'stepIgnoreErr$' -e 'chain/bridge.go:305' ;sleep 2;done ) &
  for LISTENIP in $myip;do 

    ( while (true) ;do  
     echo "RUN:" socat TCP-LISTEN:${PREFIX}${rport/:*/},bind=${LISTENIP},fork,reuseaddr TCP-CONNECT:127.0.0.1:${rport/:*/} 
      socat TCP-LISTEN:${PREFIX}${rport/:*/},bind=${LISTENIP},fork,reuseaddr TCP-CONNECT:127.0.0.1:${rport/:*/} 2>&1|sed 's/^/socat_'$rport' : /g';
      sleep 1;
     done ) &
   done
done

##perdition

touch /tmp/null;

test -e /usr/var/run/perdition.imap4s || mkdir  -p /usr/var/run/perdition.imap4s ;

 
cd /etc/perdition


test -e perdition.crt.pem || (
echo "generating dhparam"
  test -e dhparams.pem      || openssl dhparam -out dhparams.pem -dsaparam 4096 &>/dev/shm/dhparm.log &
echo "generating cert and key"
  test -e perdition.key.pem || (
   ( echo;echo;echo;echo;echo;echo;echo;echo;echo;echo;echo;echo) | openssl req -new -x509 -nodes -out perdition.crt.pem -keyout perdition.key.pem -newkey rsa:4096 -days 3650 &>/dev/shm/sslcert.log
         ) &
  wait 
cat dhparams.pem >> perdition.crt.pem
)

## imaps perdition
for rport in 993:993 ;do
#( while (true) ;do   /bridge -b :${PREFIX}${rport/:*/} -p $IMAPTARGET:${rport/*:/} -p socks5://$TORHOST:9050;sleep 2;done ) &

( while (true) ;do   
     /bridge -b :${PREFIX}${rport/*:/} -p $IMAPTARGET:${rport/*:/} -p socks5://$TORHOST:9050;sleep 2;done ) &

  for LISTENIP in $myip;do 

( while (true) ;do  
#echo  perdition.imap4s --no_daemon --ssl_mode ssl_all --connect_relog 600 --no_daemon --protocol IMAP4S -f /tmp/null  --outgoing_server $IMAPTARGET --outgoing_port ${rport/*:/} --listen_port ${rport/:*/} --bind_address=127.0.0.1 -F '+'  --pid_file /tmp/perdition.${rport/*:/}.pid --ssl_no_cert_verify --ssl_no_client_cert_verify --ssl_no_cn_verify        --tcp_keepalive
#echo  perdition.imap4s --no_daemon --ssl_mode ssl_all --connect_relog 600 --no_daemon --protocol IMAP4S -f /tmp/null  --outgoing_server 127.0.0.1 --outgoing_port ${PREFIX}${rport/*:/} --listen_port ${rport/:*/} --bind_address=127.0.0.1 -F '+'  --pid_file /tmp/perdition.${rport/*:/}.pid --ssl_no_cert_verify --ssl_no_client_cert_verify --ssl_no_cn_verify        --tcp_keepalive
#      perdition.imap4s --no_daemon --ssl_mode ssl_all --connect_relog 600 --no_daemon --protocol IMAP4S -f /tmp/null  --outgoing_server 127.0.0.1 --outgoing_port ${PREFIX}${rport/*:/} --listen_port ${rport/:*/} --bind_address=127.0.0.1 -F '+'  --pid_file /tmp/perdition.${rport/*:/}.pid --ssl_no_cert_verify --ssl_no_client_cert_verify --ssl_no_cn_verify        --tcp_keepalive
echo  perdition.imap4s --server_resp_line --no_daemon --ssl_mode ssl_all --connect_relog 600 --no_daemon --protocol IMAP4S -f /tmp/null  --outgoing_server 127.0.0.1 --outgoing_port ${PREFIX}${rport/*:/} --listen_port 93 --bind_address=${LISTENIP} -F '+'  --pid_file /tmp/perdition.${rport/*:/}.$LISTENIP.pid --ssl_no_cert_verify --ssl_no_client_cert_verify --ssl_no_cn_verify        --tcp_keepalive
      perdition.imap4s --server_resp_line --no_daemon --ssl_mode ssl_all --connect_relog 600 --no_daemon --protocol IMAP4S -f /tmp/null  --outgoing_server 127.0.0.1 --outgoing_port ${PREFIX}${rport/*:/} --listen_port 93 --bind_address=${LISTENIP} -F '+'  --pid_file /tmp/perdition.${rport/*:/}.$LISTENIP.pid --ssl_no_cert_verify --ssl_no_client_cert_verify --ssl_no_cn_verify        --tcp_keepalive 2>&1 |sed 's/^/PERDITION@'${rport}' :/g' |grep -v Connect:
sleep 1;
done ) &


( while (true) ;do  
#socat TCP-LISTEN:${rport/:*/},bind=${LISTENIP},fork,reuseaddr TCP-CONNECT:127.0.0.1:${rport/:*/} 2>&1|sed 's/^/socat_'$rport' : /g';
socat TCP-LISTEN:${rport/:*/},bind=${LISTENIP},fork,reuseaddr TCP-CONNECT:$LISTENIP:93 2>&1|sed 's/^/socat_'$rport' : /g';
sleep 1;
done ) &


( while (true) ;do  
# socat TCP-LISTEN:999,bind=${LISTENIP},fork,reuseaddr OPENSSL-CONNECT:127.0.0.1:${rport/:*/},verify=0 2>&1|sed 's/^/socat999_'$rport' : /g';
     echo "RUN:" socat TCP-LISTEN:${PREFIX}${rport/:*/},bind=${LISTENIP},fork,reuseaddr TCP-CONNECT:127.0.0.1:${rport/:*/} 
 socat TCP-LISTEN:999,bind=${LISTENIP},fork,reuseaddr OPENSSL-CONNECT:${LISTENIP}:${rport/:*/},verify=0 2>&1|sed 's/^/socat999_'$rport' : /g';
sleep 1;
done ) &

done ##end lstenip

done

## imap perdition
for rport in 143:143 ;do
#( while (true) ;do   /bridge -b :${PREFIX}${rport/:*/} -p $IMAPTARGET:${rport/*:/} -p socks5://$TORHOST:9050;sleep 2;done ) &

( while (true) ;do   
     /bridge -b :${PREFIX}${rport/*:/} -p $IMAPTARGET:${rport/*:/} -p socks5://$TORHOST:9050;sleep 2;done ) &
( while (true) ;do  
echo  perdition.imap4s --no_daemon --ssl_mode tls_all_force --connect_relog 600 --no_daemon --protocol IMAP4 -f /tmp/null  --outgoing_server 127.0.0.1 --outgoing_port ${PREFIX}${rport/*:/} --listen_port 1143 --bind_address=127.0.0.1 -F '+'  --pid_file /tmp/perdition.${rport/*:/}.$LISTENIP.pid --ssl_no_cert_verify --ssl_no_client_cert_verify --ssl_no_cn_verify        --tcp_keepalive
      perdition.imap4s --no_daemon --ssl_mode tls_all_force --connect_relog 600 --no_daemon --protocol IMAP4 -f /tmp/null  --outgoing_server 127.0.0.1 --outgoing_port ${PREFIX}${rport/*:/} --listen_port 1143 --bind_address=127.0.0.1 -F '+'  --pid_file /tmp/perdition.${rport/*:/}.$LISTENIP.pid --ssl_no_cert_verify --ssl_no_client_cert_verify --ssl_no_cn_verify        --tcp_keepalive 2>&1|sed 's/^/PERDITION@'${rport}' :/g' |grep -v Connect:
sleep 1;
done ) &

( while (true) ;do  
 socat TCP-LISTEN:${rport/:*/},bind=${LISTENIP},fork,reuseaddr TCP-CONNECT:127.0.0.1:1143 2>&1|sed 's/^/socat_'$rport' : /g';
sleep 1;
done ) &

done

echo "BOOT:COMPLETED"

##the main() ping

sleep 60 ;
while (true);do 
  for LISTENIP in $myip;do 

echo "pinging"$(
echo  "|smtp:25 :"  ;curl -kLv  smtp://${LISTENIP}:${PREFIX}025 2>&1 |grep -q -e OK -e SMTP -e STARTTLS -e AUTH= -e '^< * CAPABILITY' && echo OK |tr -d '\n'
echo  "|smtp:587:"  ;curl -kLv  smtp://${LISTENIP}:${PREFIX}587 2>&1 |grep -q -e OK -e IMAP -e STARTTLS -e AUTH= -e '^< * CAPABILITY' && echo OK |tr -d '\n'
echo  "|smtp:465:"  ;curl -kLv smtps://${LISTENIP}:${PREFIX}465 2>&1 |grep -q -e OK -e SMTP -e STARTTLS -e AUTH= -e '^< * CAPABILITY' && echo OK |tr -d '\n'
echo  "|imap:143:"  ;curl -kLv  imap://${LISTENIP}:${PREFIX}143 2>&1 |grep -q -e OK -e IMAP -e STARTTLS -e AUTH= -e '^< * CAPABILITY' && echo OK |tr -d '\n'
echo  "|imap:993:"  ;curl -kLv imaps://${LISTENIP}:${PREFIX}993 2>&1 |grep -q -e OK -e SMTP -e STARTTLS -e AUTH= -e '^< * CAPABILITY' && echo OK |tr -d '\n'
echo  "|imap:93:"   ;curl -kLv imaps://${LISTENIP}:93           2>&1 |grep -q -e OK -e SMTP -e STARTTLS -e AUTH= -e '^< * CAPABILITY' && echo OK |tr -d '\n'

)
done

sleep 1800
echo 
done

#fg;fg;fg;
#fg;fg;
wait



# cat dhparams.pem >> /etc/perdition/perdition.crt.pem );
# screen -dmS perditionsocat socat TCP-LISTEN:$PORT,bind=${myip},fork,reuseaddr TCP-CONNECT:127.0.0.1:$PORT;
#screen -dmS torsocat socat TCP-LISTEN:9050,fork,reuseaddr TCP-CONNECT:$TORGW:9050;
# perdition.imap4s --no_daemon --protocol IMAP4S -f /tmp/null  --outgoing_server 192.168.25.25 --outgoing_port 143 --explicit_domain mail.domain.lan --listen_port $PORT --bind_address=127.0.0.1:$PORT -F '+'  --pid_file /tmp/perdition.${rport/*:/}.pid --ssl_no_cert_verify --ssl_no_client_cert_verify --ssl_no_cn_verify        --tcp_keepalive

