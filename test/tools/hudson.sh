#!/bin/sh
#
# $Id$

# start Hudson in foreground
#java -jar hudson.war

# start Hudson in background
nohup java -jar hudson.war > $LOGFILE 2>&1
