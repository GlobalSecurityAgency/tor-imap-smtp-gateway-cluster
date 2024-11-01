#!/bin/bash
#echo nameserver 8.8.8.8 > /etc/resolv.conf
#echo nameserver 1.1.1.1 > /etc/resolv.conf
PREFIX=$1;

mkdir -p /var/run/dbus/ &>/dev/null
rm /etc/avahi/service/sftp-ssh.service  /etc/avahi/service/ssh.service  &>/dev/null &

rm /var/log/nginx/access.log  /var/log/nginx/error.log   /var/log/nginx/stream.log  &>/dev/null &
ln -s /dev/stdout /var/log/nginx/access.log 
ln -s /dev/stdout /var/log/nginx/stream.log 
ln -s /dev/stderr /var/log/nginx/error.log
TORHOST=$3

[[ -z "$TORHOST" ]] && TORHOST=tor.local

socat tcp-listen:9050,fork,reuseaddr tcp-connect:$TORHOST:9050 2>&1 |sed 's/^/TORCAT: /g'|grep -v "Address in use" &

#ip a |grep global|grep -v inet6|cut -d"/" -f1|cut -dt -f2 |sed "s/ //g" 
myip=$(ip a |grep global|grep -v inet6|cut -d"/" -f1|cut -dt -f2 |sed "s/ //g" )

bash /avahi-to-hosts.sh --repeat   &
dnsmasq  -f -d --strict-order --no-resolv  --server "127.0.0.11#53" --addn-hosts=/etc/hosts.mdns 2>&1 |sed 's/^/DNSMQ:/g'  &
echo nameserver 127.0.0.1 > /etc/resolv.conf
mkdir -p /etc/nginx/mail.d/
(grep ^mail /etc/nginx/nginx.conf  |grep -q mail.d ) || ( 
mkdir -p /etc/nginx/mail.d/


   echo '
mail { 
	ssl_session_cache   shared:MAILSSL:10m;
    ssl_session_timeout 10m;
    ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers         HIGH:!aNULL:!MD5;    
	   proxy_pass_error_message on;
	   include /etc/nginx/mail.d/*.conf ;
	   }
	   
	   ' >> /etc/nginx/nginx.conf  )

sleep 10;

## use smtp and imap subdomains if they exist

IMAPTARGET=$2
echo "testing imap.$2"
testme=imap.$2
foundit=no
( for nameserver in 127.0.0.1 1.1.1.1 4.2.2.4 8.8.8.8 ;do (nslookup -type=A "$testme" "$nameserver" 2>/dev/null|tail -n+3;nslookup -type=AAAA "$testme" "$nameserver" 2>/dev/null|tail -n+3) ;done |sort -u |sed 's/$/ | /g' |tr -d '\n'|grep ^Address  ) && foundit=yes   
echo "$foundit"|grep -q yes && IMAPTARGET=imap.$2;

echo "testing smtp.$2"
SMTPTARGET=$2;
testme=smtp.$2
foundit=no
( for nameserver in 127.0.0.1 1.1.1.1 4.2.2.4 8.8.8.8 ;do (nslookup -type=A "$testme" "$nameserver" 2>/dev/null|tail -n+3;nslookup -type=AAAA "$testme" "$nameserver" 2>/dev/null|tail -n+3) ;done |sort -u |sed 's/$/ | /g' |tr -d '\n'|grep ^Address  ) && foundit=yes
echo "$foundit"|grep -q yes && SMTPTARGET=smtp.$2;
echo "START: PREFIX=$1; IMAPTARGET=$IMAPTARGET; SMTPTARGET=$SMTPTARGET; TORHOST=$3 LISTEN=$myip"

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


## end bootstrap

sleepint=2

echo "NO" > /dev/shm/READY

[[ -z "$TORHOST" ]] || ( (nslookup "$TORHOST" 127.0.0.11 |tail -n+3 |grep -q ^Addr |head -n1 ) &&  ping -c3 "$TORHOST" &&  ( echo "YES" >  /dev/shm/READY ))

grep -q "$TORHOST" /etc/hosts.mdns 2>/dev/null|wc -l  |grep -q ^0$ || ( echo "YES" >   /dev/shm/READY)

while (cat /dev/shm/READY 2>/dev/null |grep ^YES$ |wc -l |grep -q ^0$ );do
echo "HOST DISCOVERY.. ( waiting $sleepint s )CURRENT AVAHI HOSTS:"$(cut -d" " -f1 /etc/hosts.mdns 2>/dev/null) 

sleepint=$(($sleepint*2))
[[ -z "$sleepint" ]] && sleepint=2
sleep $sleepint
[[  $sleepint -gt 128 ]] && sleepint=4
grep -q "$TORHOST" /etc/hosts.mdns 2>/dev/null|wc -l  |grep -q ^0$ || ( echo "YES" >   /dev/shm/READY)
[[ -z "$TORHOST" ]] || ( (nslookup "$TORHOST" 127.0.0.11 |tail -n+3 |grep -q ^Addr |head -n1 ) &&  ping -c3 "$TORHOST" &&  ( echo "YES" >  /dev/shm/READY ))|grep -e bytes -e loss 
done



while (true);do 
    nginx -g 'daemon off;' 2>&1 | grep -v -e '] TCP 200 ' ;sleep 5;
done & 


nginx_confgen_tcp() { 
	myports=$1
echo '
    server {
        listen           '${myports/:*/}' ;
        proxy_pass        127.0.0.1:'${myports/*:/}';
        proxy_buffer_size 16k;
        access_log /dev/stdout main;
    }
        
' > /etc/nginx/stream.d/${myports//:/_}.conf
echo -n ; } ; 


nginx_confgen() { 
	myports=$1
	myssl=""
	echo $myports|cut -d":" -f1 |grep -q -e 587$ -e 25$  &&  myssl="starttls on;"
	echo $myports|cut -d":" -f1 |grep -q -e 587$ -e 25$  &&  myproto="smtp"

	echo $myports|cut -d":" -f1 |grep -q -e 465$   &&  myssl="ssl on;"
	echo $myports|cut -d":" -f1 |grep -q -e 465$   &&  myproto="smtps"
	
		
	echo $myports|cut -d":" -f1 |grep -q -e 143$   &&  myssl="starttls on;"
	echo $myports|cut -d":" -f1 |grep -q -e 143$   &&  myproto="imap"

	
	echo $myports|cut -d":" -f1 |grep -q -e 93$   &&  myssl="ssl on;"
	echo $myports|cut -d":" -f1 |grep -q -e 93$   &&  myproto="imaps"

echo "$myproto"|grep -q smtp && (
echo '
    server {
        listen           '${myports/:*/}' ;
        proxy_pass        127.0.0.1:'${myports/*:/}';
        proxy_buffer_size 16k;
        access_log /dev/stdout main;
    }
        
' > /etc/nginx/stream.d/${myports//:/_}.conf

 )
echo "$myproto"|grep -q imap && ( (
echo ' 
 server {

     listen '${myports/:*/}' ;
    server_name '$IMAPTARGET';
    '"$myssl"'
    ssl_certificate     /etc/perdition/perdition.crt.pem;
    ssl_certificate_key /etc/perdition/perdition.key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"; 
    proxy_pass '"$myproto"'://127.0.0.1:'${myports/*:/}';
    proxy_set_header Host $host;
    #proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Real-IP 127.0.0.1;
    #proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-For 127.0.0.1;
    proxy_set_header X-Forwarded-Proto $scheme; 

echo ' } '
    
    ) > /etc/nginx/mail.d/${myports//:/_}.conf )

    
echo -n ; } ; 
## bridge 

(

## smtp bridge
#for  rport in ${PREFIX}587:587 ${PREFIX}465:465;do 
for  rport in ${PREFIX}587:587 ${PREFIX}465:465;do 
  ( while (true) ;do   /bridge -b :${rport/:*/} -p $SMTPTARGET:${rport/*:/} -p socks5://$TORHOST:9050 2>&1 |grep -v -e "INFO Connect chains" -e remote_address=127.0.0.1 -e '"remote_address": "127.0.0.1:' -e 'stepIgnoreErr$' -e 'chain/bridge.go:305' -e "i/o timeout" ;sleep 2;done ) &
done

#for rport in 587:${PREFIX}587 25:${PREFIX}587;do 
#nginx_confgen "$rport"
#nginx -t && nginx -s reload 
#done 
##nginx -t && nginx -s reload 

) & #end bridge

##perdition
(
touch /tmp/null;

test -e /usr/var/run/perdition.imap4s || mkdir  -p /usr/var/run/perdition.imap4s ;

 
cd /etc/perdition


ls -1   /etc/perdition/perdition.crt.pem || (
  ls -1 /etc/perdition/dhparams.pem      ||  ( echo "generating dhparam" ;
                                  openssl dhparam -out /etc/perdition/dhparams.pem -dsaparam 4096 &>/dev/shm/dhparm.log ) &
  ls -1 /etc/perdition/perdition.key.pem || (   echo "generating cert and key"
                                 ( echo;echo;echo;echo;echo;echo;echo;echo;echo;echo;echo;echo) | openssl req -new -x509 -nodes -out /etc/perdition/perdition.crt.pem -keyout /etc/perdition/perdition.key.pem -newkey rsa:4096 -days 3650 &>/dev/shm/sslcert.log
                                 
                               ) &
  wait 
  grep "DH PARAMETERS" /etc/perdition/perdition.crt.pem || ( cat /etc/perdition/dhparams.pem >> /etc/perdition/perdition.crt.pem )
)
echo "FORK PERDITIONs"
## imaps perdition
for rport in 993:993 ;do
#( while (true) ;do   /bridge -b :${PREFIX}${rport/:*/} -p $IMAPTARGET:${rport/*:/} -p socks5://$TORHOST:9050;sleep 2;done ) &

( while (true) ;do   
     /bridge -b :${PREFIX}${rport/*:/} -p $IMAPTARGET:${rport/*:/} -p socks5://127.0.0.1:9050 2>&1  |grep -v -e "INFO Connect chains" -e remote_address=127.0.0.1 -e '"remote_address": "127.0.0.1:' -e 'stepIgnoreErr$' -e 'chain/bridge.go:305' -e "i/o timeout" ;sleep 2;done ) &

( while (true) ;do  
LISTENIP=127.0.0.1
#rport=193:993
#rport=193:${PREFIX}993
rport=193:999
## socat will send sni for us 

#echo  perdition.imap4s --no_daemon --ssl_mode ssl_all --connect_relog 600 --no_daemon --protocol IMAP4S -f /tmp/null  --outgoing_server $IMAPTARGET --outgoing_port ${rport/*:/} --listen_port ${rport/:*/} --bind_address=127.0.0.1 -F '+'  --pid_file /tmp/perdition.${rport/*:/}.pid --ssl_no_cert_verify --ssl_no_client_cert_verify --ssl_no_cn_verify        --tcp_keepalive
#echo  perdition.imap4s --no_daemon --ssl_mode ssl_all --connect_relog 600 --no_daemon --protocol IMAP4S -f /tmp/null  --outgoing_server 127.0.0.1 --outgoing_port ${PREFIX}${rport/*:/} --listen_port ${rport/:*/} --bind_address=127.0.0.1 -F '+'  --pid_file /tmp/perdition.${rport/*:/}.pid --ssl_no_cert_verify --ssl_no_client_cert_verify --ssl_no_cn_verify        --tcp_keepalive
#      perdition.imap4s --no_daemon --ssl_mode ssl_all --connect_relog 600 --no_daemon --protocol IMAP4S -f /tmp/null  --outgoing_server 127.0.0.1 --outgoing_port ${PREFIX}${rport/*:/} --listen_port ${rport/:*/} --bind_address=127.0.0.1 -F '+'  --pid_file /tmp/perdition.${rport/*:/}.pid --ssl_no_cert_verify --ssl_no_client_cert_verify --ssl_no_cn_verify        --tcp_keepalive
echo  perdition.imap4s --server_resp_line --no_daemon --ssl_mode ssl_all --connect_relog 600 --no_daemon --protocol IMAP4S -f /tmp/null  --outgoing_server 127.0.0.1 --outgoing_port ${rport/*:/} --listen_port 193 --bind_address=${LISTENIP} -F '+'  --pid_file /tmp/perdition.${rport/*:/}.$LISTENIP.pid --ssl_no_cert_verify --ssl_no_client_cert_verify --ssl_no_cn_verify        --tcp_keepalive
      perdition.imap4s --server_resp_line --no_daemon --ssl_mode ssl_all --connect_relog 600 --no_daemon --protocol IMAP4S -f /tmp/null  --outgoing_server 127.0.0.1 --outgoing_port ${rport/*:/} --listen_port 193 --bind_address=${LISTENIP} -F '+'  --pid_file /tmp/perdition.${rport/*:/}.$LISTENIP.pid --ssl_no_cert_verify --ssl_no_client_cert_verify --ssl_no_cn_verify        --tcp_keepalive 2>&1 |sed 's/^/PERDITION@'${rport}' :/g' |grep -v -e Connect: -e "Closing NULL session:" -e "Fatal error establishing SSL connection to client"
sleep 1;
done ) &

done 

( while (true) ;do  
LISTENIP=127.0.0.1
rport=1143:143
echo  perdition.imap4s --no_daemon --ssl_mode tls_all_force --connect_relog 600 --no_daemon --protocol IMAP4 -f /tmp/null  --outgoing_server 127.0.0.1 --outgoing_port ${PREFIX}${rport/*:/} --listen_port 1144 --bind_address=127.0.0.1 -F '+'  --pid_file /tmp/perdition.${rport/*:/}.$LISTENIP.pid --ssl_no_cert_verify --ssl_no_client_cert_verify --ssl_no_cn_verify        --tcp_keepalive
      perdition.imap4s --no_daemon --ssl_mode tls_all_force --connect_relog 600 --no_daemon --protocol IMAP4 -f /tmp/null  --outgoing_server 127.0.0.1 --outgoing_port ${PREFIX}${rport/*:/} --listen_port 1144 --bind_address=127.0.0.1 -F '+'  --pid_file /tmp/perdition.${rport/*:/}.$LISTENIP.pid --ssl_no_cert_verify --ssl_no_client_cert_verify --ssl_no_cn_verify        --tcp_keepalive 2>&1|sed 's/^/PERDITION@'${rport}' :/g' |grep -v -e Connect: -e "Closing NULL session:" -e "Fatal error establishing SSL connection to client"
sleep 1;
done ) &



#for rport in 25:${PREFIX}587 587:${PREFIX}587 1143:1144 143:1144 93:193 993:193;do 
for rport in 25:${PREFIX}587 587:${PREFIX}587 1143:1144 143:1144 93:999 993:193;do 
nginx_confgen "$rport"
nginx -t &>/dev/null || ( echo "NGINX_ERROR: AFTER LOADING $rport" >&2 ;nginx -t)
done 
nginx -t && nginx -s reload 

) & ## end perdition


## SOCAT
(
## port 999 will accept unencrypted connections and send them via ssl 
( while (true) ;do  
rport=999:${PREFIX}993
# socat TCP-LISTEN:999,bind=${LISTENIP},fork,reuseaddr OPENSSL-CONNECT:127.0.0.1:${rport/:*/},verify=0 2>&1|sed 's/^/socat999_'$rport' : /g';
#    echo "RUN:"  socat TCP-LISTEN:${rport/:*/},bind=${LISTENIP},fork,reuseaddr OPENSSL-CONNECT:127.0.0.1:${rport/*:/},snihost=$IMAPTARGET,verify=0 
     echo "RUN:"  socat TCP-LISTEN:${rport/:*/},fork,reuseaddr OPENSSL-CONNECT:127.0.0.1:${rport/*:/},snihost=$IMAPTARGET,verify=0 
                  socat TCP-LISTEN:${rport/:*/},fork,reuseaddr OPENSSL-CONNECT:127.0.0.1:${rport/*:/},snihost=$IMAPTARGET,verify=0  2>&1|sed 's/^/socat999_'$rport' : /g';
sleep 1;
done ) &

)

nginx -T|grep -e 25 -e 587 -e 993 -e 143 

echo "BOOT:COMPLETED"

##the main() ping

sleep 60 ;
while (true);do 
  for LISTENIP in $myip;do 

echo $(date -u )" | CHECK: $LISTENIP |"$(
#echo  "|smtp:25 :"           ;curl -kLv  smtp://${LISTENIP}:${PREFIX}025 2>&1 |grep -q -e OK -e SMTP -e STARTTLS -e AUTH= -e '^< * CAPABILITY' && echo OK |tr -d '\n'
echo  "|smtp:25 :"           ;curl -kLv  smtp://${LISTENIP}:25 2>&1 |grep -q -e OK -e SMTP -e STARTTLS -e AUTH= -e '^< * CAPABILITY' && echo OK |tr -d '\n'
echo  "|smtp:587:"           ;curl -kLv  smtp://${LISTENIP}:587          2>&1 |grep -q -e OK -e IMAP -e STARTTLS -e AUTH= -e '^< * CAPABILITY' && echo OK |tr -d '\n'
#echo  "|smtp:${PREFIX}587:"  ;curl -kLv  smtp://${LISTENIP}:${PREFIX}587 2>&1 |grep -q -e OK -e IMAP -e STARTTLS -e AUTH= -e '^< * CAPABILITY' && echo OK |tr -d '\n'
echo  "|smtp:465:"           ;curl -kLv smtps://${LISTENIP}:465          2>&1 |grep -q -e OK -e SMTP -e STARTTLS -e AUTH= -e '^< * CAPABILITY' && echo OK |tr -d '\n'
echo  "|imap:143:"           ;curl -kLv  imap://${LISTENIP}:143          2>&1 |grep -q -e OK -e IMAP -e STARTTLS -e AUTH= -e '^< * CAPABILITY' && echo OK |tr -d '\n'
echo  "|imap:${PREFIX}143:"  ;curl -kLv    imap://127.0.0.1:${PREFIX}143 2>&1 |grep -q -e OK -e IMAP -e STARTTLS -e AUTH= -e '^< * CAPABILITY' && echo OK |tr -d '\n'
echo  "|imap:1143:"          ;curl -kLv  imap://${LISTENIP}:1143         2>&1 |grep -q -e OK -e IMAP -e STARTTLS -e AUTH= -e '^< * CAPABILITY' && echo OK |tr -d '\n'
echo  "|imap:93:"            ;curl -kLv imaps://${LISTENIP}:93           2>&1 |grep -q -e OK -e SMTP -e STARTTLS -e AUTH= -e '^< * CAPABILITY' && echo OK |tr -d '\n'
echo  "|imap:193:"           ;curl -kLv   imaps://127.0.0.1:193          2>&1 |grep -q -e OK -e SMTP -e STARTTLS -e AUTH= -e '^< * CAPABILITY' && echo OK |tr -d '\n'
echo  "|imap:993:"           ;curl -kLv imaps://${LISTENIP}:993          2>&1 |grep -q -e OK -e SMTP -e STARTTLS -e AUTH= -e '^< * CAPABILITY' && echo OK |tr -d '\n'
echo  "|imap:${PREFIX}993:"  ;curl -kLv   imaps://127.0.0.1:${PREFIX}993 2>&1 |grep -q -e OK -e SMTP -e STARTTLS -e AUTH= -e '^< * CAPABILITY' && echo OK |tr -d '\n'

) |tr -d '\n';echo
done

sleep 1800
echo 
done
wait

# cat dhparams.pem >> /etc/perdition/perdition.crt.pem );
# screen -dmS perditionsocat socat TCP-LISTEN:$PORT,bind=${myip},fork,reuseaddr TCP-CONNECT:127.0.0.1:$PORT;
#screen -dmS torsocat socat TCP-LISTEN:9050,fork,reuseaddr TCP-CONNECT:$TORGW:9050;
# perdition.imap4s --no_daemon --protocol IMAP4S -f /tmp/null  --outgoing_server 192.168.25.25 --outgoing_port 143 --explicit_domain mail.domain.lan --listen_port $PORT --bind_address=127.0.0.1:$PORT -F '+'  --pid_file /tmp/perdition.${rport/*:/}.pid --ssl_no_cert_verify --ssl_no_client_cert_verify --ssl_no_cn_verify        --tcp_keepalive


