#!/bin/sh

if [ ! -x /jffs/bin/wiomw-start ]
then
	if [ ! -d /jffs/bin ]
	then
		mkdir /jffs/bin
	fi
	cd /jffs/bin
	wget 'https://www.whoisonmywifi.net/downloads/wiomw-start'
	chmod +x wiomw-start
	cd -
fi
if [ ! -d /tmp/var/wwwext ]
then
	mkdir /tmp/var/wwwext
fi
/jffs/bin/wiomw-start 2> /tmp/var/wwwext/wiomw-start.log &

