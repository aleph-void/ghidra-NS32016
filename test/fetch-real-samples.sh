#!/usr/bin/env bash
# Download the NetBSD 1.5 pc532 (NS32532) base and comp sets, check their SHA-256 and unpack them.
#   test/fetch-real-samples.sh <dir>
# The sets are BSD-licensed (NetBSD); they are test inputs only and are never committed.
set -euo pipefail
DIR=$(readlink -m "${1:?usage: fetch-real-samples.sh <dir>}")
URL=https://archive.netbsd.org/pub/NetBSD-archive/NetBSD-1.5/pc532/binary/sets
mkdir -p "$DIR"
cd "$DIR"
declare -A SHA=(
	[base.tgz]=ab8ec9c79601cdd2168fd34965d0d31076818f36d0472073bf31f1eb647e2be7
	[comp.tgz]=0db3118303460ef2471c9b8b8d271d0c9a5fc06aa4a0ebd5d50425499c2f9682
)
for set in base comp; do
	f=$set.tgz
	[[ -f $f ]] || curl -fsSL -o "$f" "$URL/$f"
	echo "${SHA[$f]}  $f" | sha256sum -c -
	[[ -d $set ]] || { mkdir "$set"; tar xzf "$f" -C "$set"; }
done
echo "samples in $DIR/base and $DIR/comp"
