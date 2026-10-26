#!/usr/bin/env bash
# Compile the module's Java (the a.out loader) into lib/NS32016.jar so that a Ghidra install with this
# directory linked or copied under Ghidra/Processors/NS32016 picks it up (Ghidra loads <module>/lib/*.jar).
# The release route is `gradle buildExtension`; this is the quick path for the test harness.
#   GHIDRA_INSTALL_DIR=... test/build-jar.sh
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
MOD=$(cd "$(dirname "$0")/.." && pwd)
G=$GHIDRA_INSTALL_DIR/Ghidra
CP=$(find "$G/Framework" "$G/Features/Base" -name '*.jar' ! -name '*-src*' | tr '\n' ':')
JAVAC=javac
[[ -n ${JAVA_HOME:-} ]] && JAVAC=$JAVA_HOME/bin/javac
OUT=$(mktemp -d "${TMPDIR:-/tmp}/ns32016-jar.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
"$JAVAC" -nowarn --release 21 -cp "$CP" -d "$OUT" $(find "$MOD/src/main/java" -name '*.java')
mkdir -p "$MOD/lib"
JAR=jar
[[ -n ${JAVA_HOME:-} ]] && JAR=$JAVA_HOME/bin/jar
# build next to the jar and rename it into place, so running Ghidra JVMs keep the old file
"$JAR" cf "$MOD/lib/NS32016.jar.new" -C "$OUT" .
mv "$MOD/lib/NS32016.jar.new" "$MOD/lib/NS32016.jar"
echo "built $MOD/lib/NS32016.jar"
