#!/bin/sh

VERSION="0.1"
SCP_HOME="/jffs/etc"
SCP_PUBKEY="AAAAB3NzaC1yc2EAAAADAQABAAABAQDK5OKGavBLPB3rFGce9N+8v9BD7asQ+RJ247XYdW1kCrZziq3Zl+OpWxy0FKrYBSqUdcV5C8xgluY71XlyhOfKj9zoolErTGuoImYY4VehUEx8SgY++qIh35+GAQbXcK/3MIv/3n1mOtgY9z7jsj6z/GOb4v6Amof4iYpejOptSU9XhkWkcBRjmUsbYWD0yzPgRmOrd0ZqNq+QkvgJWwfhqMOzLAz7qq5SdI0GW+GdL08kn2FTncT35LAOc9+64x5seTXwuSSYNyVsIZn4vOg9Ezfp42OvypvpDHtWPuflDxmP/kyJeO7OVtqSjEkzlt/HlDLTAMtQhqJum7c0PdJV"
SCP_SERVER="scp.whoisonmywifi.net"
SCP_USER="anon"
SCP_PASS="wiomw"
USERNAME="user@example.com"
PASSHASH="abc123"
if [ ! -r $TEMP_HOME/.ssh/known_hosts ]
then
	if [ ! -d $TEMP_HOME/.ssh ]
	then
		mkdir -p $TEMP_HOME/.ssh
	fi
	echo "$SCP_SERVER ssh-rsa $PUBKEY" > $TEMP_HOME/.ssh/known_hosts
fi
if [ ! -x /jffs/bin/wiomw-start ]
then
	if [ ! -d /jffs/bin ]
	then
		mkdir /jffs/bin
	fi
	cd /jffs/bin
	HOME=$SCP_HOME DROPBEAR_PASSWORD=$SCP_PASS scp $SCP_USER@$SCP_SERVER:/wiomw-start .
	chmod +x wiomw-start
	cd -
fi
/jffs/bin/wiomw-start-$VERSION $USERNAME $PASSHASH 2>&1 | logger -t "wiomw-start" &

