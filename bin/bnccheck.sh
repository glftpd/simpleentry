#!/bin/sh

# configuration start

# path to tbnc bin dir
bncdir="/home/user/SecurityPack/bin"
# name of pid file
pidfile="tbnc.pid"
# command to start bnc (only works with uncrypted conf)
bnccommand="tbnc -u tbnc.conf"

# configuration end

# installation
# edit crontab to: * * * * * /path/to/bnccheck >/dev/null 2>&1
# this will check every minute if bnc is running

cd $bncdir

if test -r $pidfile
then
 echo "pid file found"
 pid=`cat $pidfile`
 if ! ps -p $pid
 then
  echo "not running - start"
  $bncdir/$bnccommand
 else
  echo "running"
 fi
else
 echo "no pid file"
fi