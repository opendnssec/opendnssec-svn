#!/bin/sh
#
# $Id$

# Build and test OpenDNSSEC
# Uses $HOME/ODS for install sandbox
rm -rf $HOME/ODS

echo cd opendnssec/softHSM
echo sh autogen.sh
echo ./configure --prefix=$HOME/ODS --with-botan=/opt/local/var/macports/software/botan/1.8.7_0+darwin/opt/local/
echo make check
echo make install
echo cd ../OpenDNSSEC

sh autogen.sh
echo ./configure --prefix=$HOME/ODS --with-pkcs11-softhsm=$HOME/ODS/lib/libsofthsm.so
./configure --prefix=$HOME/ODS --with-pkcs11-softhsm=/usr/local/lib/libsofthsm.so
make install

make check 

export SOFTHSM_CONF=test/scripts/softhsm.conf

echo "yes" | $HOME/ODS/bin/ods-ksmutil setup

echo $HOME/ODS/bin/softhsm --init-token --slot 0  --pin 1234 --so-pin 1234 --label "OpenDNSSEC"
softhsm --init-token --slot 0  --pin 1234 --so-pin 1234 --label "OpenDNSSEC"

cp test/zonedata/unknown.rr.org $HOME/ODS/var/opendnssec/unsigned/.
$HOME/ODS/bin/ods-ksmutil zone add -z  unknown.rr.org -p default
cp test/zonedata/example.com $HOME/ODS/var/opendnssec/unsigned/.
$HOME/ODS/bin/ods-ksmutil zone add -z  example.com -p default
cp test/zonedata/all.rr.org $HOME/ODS/var/opendnssec/unsigned/.
$HOME/ODS/bin/ods-ksmutil zone add -z  all.rr.org -p default
cp test/zonedata/all.rr.binary.org $HOME/ODS/var/opendnssec/unsigned/.
$HOME/ODS/bin/ods-ksmutil zone add -z  all.rr.binary.org -p default
$HOME/ODS/bin/ods-ksmutil update all
$HOME/ODS/bin/ods-ksmutil key generate --interval P1Y --policy default

# TODO - this should be replaced by ods-control start when it is fixed
$HOME/ODS/sbin/ods-enforcerd -1
sleep 5
$HOME/ODS/sbin/ods-enforcerd 
sleep 5
$HOME/ODS/sbin/ods-signerd
sleep 5
$HOME/ODS/sbin/ods-signer zones
sleep 1
$HOME/ODS/sbin/ods-signer sign unknown.rr.org
$HOME/ODS/sbin/ods-signer sign example.com
echo $HOME/ODS/sbin/ods-signer sign all.rr.org
echo $HOME/ODS/sbin/ods-signer sign all.rr.binary.org
sleep 5

$HOME/ODS/sbin/ods-control stop

echo "NOW CHECK THAT ZONES HAVE BEEN SIGNED"
test/scripts/check_zones_exist unknown.rr.org example.com
echo Still to check all.rr.org and all.rr.binary.org
