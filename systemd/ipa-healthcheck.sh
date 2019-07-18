#!/bin/sh

LOGDIR=/var/log/ipa/healthcheck

/usr/bin/ipa-healthcheck --output-file $LOGDIR/healthcheck.log
