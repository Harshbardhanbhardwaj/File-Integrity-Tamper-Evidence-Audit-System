#!/usr/bin/env bash
# End-to-end system test of the fiaudit CLI (uses the in-memory device model: --device sim
# is per-process, so cross-process kernel checks are covered in the unit tests / driver tests).
set -u
BIN="${BIN:-$(dirname "$0")/../bin/fiaudit}"
WORK="$(mktemp -d)"
trap 'kill $WPID 2>/dev/null; rm -rf "$WORK"' EXIT
TREE="$WORK/tree"; STATE="$WORK/state"; mkdir -p "$TREE/sub" "$STATE"
B="$STATE/base"; L="$STATE/log"
pass=0; fail=0
ok()   { echo "  PASS: $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL: $1"; fail=$((fail+1)); }
expect_rc() { # desc expected_rc cmd...
  local d="$1" want="$2"; shift 2
  "$@" >"$WORK/out" 2>&1; local rc=$?
  if [ "$rc" -eq "$want" ]; then ok "$d (rc=$rc)"; else bad "$d (rc=$rc, wanted $want)"; cat "$WORK/out"; fi
}

echo "alpha" > "$TREE/a.txt"; echo "bravo" > "$TREE/sub/b.txt"; echo "x" > "$TREE/skip.tmp"
D="--device none"

echo "== init / check =="
expect_rc "init creates baseline" 0 "$BIN" init "$TREE" --baseline "$B" --log "$L" --exclude '*.tmp' $D
expect_rc "check clean tree"     0 "$BIN" check --baseline "$B" $D
echo "TAMPER" > "$TREE/a.txt"; rm "$TREE/sub/b.txt"; echo new > "$TREE/c.txt"; echo y > "$TREE/ignored.tmp"
expect_rc "check detects changes" 1 "$BIN" check --baseline "$B" $D
grep -q "MODIFIED.*a.txt" "$WORK/out" && ok "reports MODIFIED a.txt" || bad "MODIFIED a.txt"
grep -q "DELETED.*b.txt"  "$WORK/out" && ok "reports DELETED b.txt"  || bad "DELETED b.txt"
grep -q "ADDED.*c.txt"    "$WORK/out" && ok "reports ADDED c.txt"    || bad "ADDED c.txt"
grep -q "ignored.tmp"     "$WORK/out" && bad "excluded file leaked"  || ok "exclude pattern honoured"
expect_rc "check --json" 1 "$BIN" check --baseline "$B" --json $D
grep -q '"kind":"MODIFIED"' "$WORK/out" && ok "json output well-formed" || bad "json output"

echo "== baseline tamper detection =="
cp "$B" "$B.bak"; sed -i 's/^T\t/T\t9/' "$B"
expect_rc "tampered baseline rejected" 2 "$BIN" check --baseline "$B" $D
cp "$B.bak" "$B"

echo "== log verification =="
expect_rc "log chain valid" 0 "$BIN" verify-log --log "$L" --device none
cp "$L" "$L.bak"; sed -i '1s/baseline created/baseline CREATED/' "$L"
expect_rc "modified log detected" 1 "$BIN" verify-log --log "$L" --device none
cp "$L.bak" "$L"

echo "== watch (live monitoring) =="
# restore tree to baseline state first
echo alpha > "$TREE/a.txt"; echo bravo > "$TREE/sub/b.txt"; rm -f "$TREE/c.txt" "$TREE/ignored.tmp"
"$BIN" watch --baseline "$B" --log "$L" --device none --debounce 100 >"$WORK/watch.out" 2>&1 &
WPID=$!
sleep 1
echo "evil" > "$TREE/a.txt"
rm "$TREE/sub/b.txt"
mkdir -p "$TREE/newdir"; echo '#!/bin/sh' > "$TREE/newdir/backdoor.sh"
chmod 777 "$TREE/sub" 2>/dev/null
sleep 1.5
kill -TERM $WPID; wait $WPID; rc=$?
[ "$rc" -eq 0 ] && ok "watch exits 0 on SIGTERM" || bad "watch exit code $rc"
"$BIN" show-log --log "$L" --tail 50 > "$WORK/show.out"
grep -q "MODIFY .*a.txt"            "$WORK/show.out" && ok "live MODIFY logged"  || bad "live MODIFY"
grep -q "DELETE .*b.txt"            "$WORK/show.out" && ok "live DELETE logged"  || bad "live DELETE"
grep -q "CREATE .*backdoor.sh"      "$WORK/show.out" && ok "live CREATE in new dir logged" || bad "live CREATE"
expect_rc "log valid after watch" 0 "$BIN" verify-log --log "$L" --device none

echo "== watch refuses broken log =="
sed -i '2s/SCAN/XXXX/' "$L"
expect_rc "watch refuses tampered log" 2 "$BIN" watch --baseline "$B" --log "$L" --device none
cp "$L.bak" "$L"

echo "== usage errors =="
expect_rc "unknown option" 64 "$BIN" check --bogus
expect_rc "unknown command" 64 "$BIN" frobnicate

echo
echo "integration: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
