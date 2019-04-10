#!/bin/sh
LOGDIR=/var/log/ipa/healthcheck
DATE=$(date +%Y%m%d)

/usr/bin/ipa-healthcheck --output-file $LOGDIR/healthcheck.log-$DATE
