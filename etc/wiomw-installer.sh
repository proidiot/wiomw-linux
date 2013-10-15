#!/bin/sh

VERSION="1.0"
SCP_HOME="/jffs/etc"
SCP_PUBKEY="AAAAB3NzaC1yc2EAAAADAQABAAABAQDbaCdcMqXJmP53Jg1IG7ZmGyP+vtl7dtEYgleG5bmY84U3YAqV3LJ+yhs0xkdfOJ11mawol+tYXkKyYJsR32A5GKXTk/3p7BzqvrdFXa4TwIZ6MOhI7mtVV+cZ/d5Cn1rYfjPKVpsuj6pwvQ+vRa8lJAEHXp5Fjl6/iY5P4T10pGepGWhHnc0DNaJH1x6DOG4jVo3l73Qyr0vqTHg8ZqL/HD9dNTzCPM7Zic3XjODzsyAzeaam94jVACG1rS4FBwMtI70PWonrCmWeNwBKAImu67pX4V/OoOKOHcvUWJVmGH2wxmxojfi5YMI9bmA7xzfYxy3aHHLb6FKxAkul0vVf"
SCP_SERVER="54.235.89.158"
SCP_USER="anon"
SCP_PASS="wiomw"
USERNAME="user@example.com"
PASSHASH="abc123"
AGENTKEY="agent007"
if [ ! -r $SCP_HOME/.ssh/known_hosts ]
then
	if [ ! -d $SCP_HOME/.ssh ]
	then
		mkdir -p $SCP_HOME/.ssh
	fi
	echo "$SCP_SERVER ssh-rsa $SCP_PUBKEY" > $SCP_HOME/.ssh/known_hosts
fi
if [ ! -x /jffs/bin/wiomw-start-$VERSION ]
then
	if [ ! -d /jffs/bin ]
	then
		mkdir /jffs/bin
	fi
	cd /jffs/bin
	HOME=$SCP_HOME DROPBEAR_PASSWORD=$SCP_PASS scp $SCP_USER@$SCP_SERVER:wiomw-start-$VERSION .
	chmod +x wiomw-start-$VERSION
	cd -
fi
/jffs/bin/wiomw-start-$VERSION $USERNAME $PASSHASH $AGENTKEY 2>&1 | logger -t "wiomw-start" &

