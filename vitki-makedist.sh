#!/bin/sh
#set -x
SPEC=ipguard.spec
[ ! -r $SPEC ] && echo "$SPEC: cannot open" && exit
VER=`cat $SPEC | grep Version: | head -1 | awk '{print $2}'`
TARBALL="../ipguard-${VER}.tar.gz"
echo version: $VER $SVNVER
tar -cz -f $TARBALL --exclude .svn --exclude ipguardd --exclude `basename $0` *
echo $TARBALL
