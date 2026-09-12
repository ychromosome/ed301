#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

# Derived from the bound v1 verifier. The D2 controller binds its source
# snapshot; the caller supplies the unchanged outer OpenSSL evidence digest.

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <lane-root> <3.5.8|4.0.2> <evidence-manifest-sha256>" >&2
    exit 2
fi

ROOT_ARG=$1
VERSION=$2
EXPECTED=$3
case "$VERSION" in
    3.5.8) EXPECTED_TAR=a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2 ;;
    4.0.2) EXPECTED_TAR=736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8 ;;
    *) echo "unsupported OpenSSL lane: $VERSION" >&2; exit 2 ;;
esac
if ! printf '%s\n' "$EXPECTED" | grep -Eq '^[0-9a-f]{64}$'; then
    echo "lane evidence digest must be an external lowercase SHA-256" >&2
    exit 2
fi
if printf '%s\n' "$ROOT_ARG" | grep -q '[[:cntrl:]]'; then
    echo "lane root contains a control character" >&2
    exit 2
fi
test -d "$ROOT_ARG" && test ! -L "$ROOT_ARG" || {
    echo "lane root must be a non-symlink directory" >&2
    exit 1
}
ROOT=$(readlink -f -- "$ROOT_ARG")
PREFIX=$ROOT/inst/$VERSION
LOGS=$ROOT/logs/$VERSION
MANIFEST=$LOGS/evidence_manifest.sha256
SOURCE=$ROOT/src/openssl-$VERSION

for directory in "$ROOT/inst" "$ROOT/logs" "$ROOT/src" "$ROOT/input"; do
    test -d "$directory" && test ! -L "$directory"
done
test -f "$MANIFEST" && test ! -L "$MANIFEST"
test -f "$ROOT/input/openssl-$VERSION.tar.gz" \
    && test ! -L "$ROOT/input/openssl-$VERSION.tar.gz"
test "$(sha256sum "$ROOT/input/openssl-$VERSION.tar.gz" | awk '{ print $1 }')" \
    = "$EXPECTED_TAR"
test -d "$PREFIX" && test ! -L "$PREFIX" \
    && test -d "$LOGS" && test ! -L "$LOGS" || {
    echo "lane prefix or evidence directory is unsafe" >&2
    exit 1
}
test "$(cat "$LOGS/lane_status")" = "LANE $VERSION OK"
test "$(cat "$LOGS/lane_status.exit")" = 0

ACTUAL=$(sha256sum "$MANIFEST" | awk '{print $1}')
[ "$ACTUAL" = "$EXPECTED" ] || {
    echo "OpenSSL lane evidence does not match the external seal" >&2
    echo "expected: $EXPECTED" >&2
    echo "actual:   $ACTUAL" >&2
    exit 1
}
(cd "$ROOT" && sha256sum --strict --quiet -c \
    "logs/$VERSION/evidence_manifest.sha256")

# The provider acceptance lane also reuses OpenSSL's native evp_test binary.
# Bind that executable to the already externally sealed post-build source
# manifest instead of trusting an arbitrary file under the lane directory.
# The historical seals contain old absolute staging paths. Authenticate their
# bytes via the outer evidence manifest above, then bind their exact declared
# members to the current logs directory without modifying any old artifact.
python3 -I -B - "$LOGS" <<'PY'
import hashlib
from pathlib import Path
import re
import sys

logs = Path(sys.argv[1])
sets = {
    "source_manifest_post.sha256.seal": {"source_manifest_post.sha256"},
    "installed_prefix_manifest.seal": {
        "installed_prefix.sha256", "installed_prefix_files.lst",
        "installed_prefix_directories.lst", "installed_prefix_symlinks.tsv"},
}
origin = None
for seal, names in sets.items():
    seen = set()
    for line in (logs / seal).read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (/[^\r\n]+)", line)
        if match is None:
            raise SystemExit("invalid legacy seal entry")
        expected, old = match.groups()
        name = Path(old).name
        suffix = f"/logs/{logs.name}/{name}"
        if name not in names or name in seen or not old.endswith(suffix):
            raise SystemExit("unexpected or duplicate legacy seal member")
        old_origin = old[:-len(suffix)]
        if origin is None:
            origin = old_origin
        if old_origin != origin:
            raise SystemExit("legacy seals disagree on their source root")
        member = logs / name
        if member.is_symlink() or not member.is_file():
            raise SystemExit("legacy seal member is not a regular file")
        if hashlib.sha256(member.read_bytes()).hexdigest() != expected:
            raise SystemExit(f"legacy seal hash mismatch: {name}")
        seen.add(name)
    if seen != names:
        raise SystemExit("legacy seal member inventory mismatch")
print("relocated_legacy_seals=PASS (original seal bytes unchanged)")
PY
test -d "$SOURCE" && test ! -L "$SOURCE"
test -x "$SOURCE/test/evp_test" && test ! -L "$SOURCE/test/evp_test"
EVP_TEST_EXPECTED=$(awk '$2 == "./test/evp_test" { print $1 }' \
    "$LOGS/source_manifest_post.sha256")
test -n "$EVP_TEST_EXPECTED"
test "$(sha256sum "$SOURCE/test/evp_test" | awk '{ print $1 }')" \
    = "$EVP_TEST_EXPECTED"
MLKEM_DATA=./test/recipes/30-test_evp_data/evppkey_ml_kem_encap_decap.txt
MLKEM_DATA_EXPECTED=$(awk -v path="$MLKEM_DATA" \
    '$2 == path { print $1 }' "$LOGS/source_manifest_post.sha256")
test -n "$MLKEM_DATA_EXPECTED"
test -f "$SOURCE/${MLKEM_DATA#./}" \
    && test ! -L "$SOURCE/${MLKEM_DATA#./}"
test "$(sha256sum "$SOURCE/${MLKEM_DATA#./}" | awk '{ print $1 }')" \
    = "$MLKEM_DATA_EXPECTED"

grep -Fqx "lane=$VERSION" "$LOGS/lane_identity.seal"
grep -Fqx "prefix_rel=inst/$VERSION" "$LOGS/lane_identity.seal"
grep -Fqx "installed_prefix_manifest_rel=logs/$VERSION/installed_prefix.sha256" \
    "$LOGS/lane_identity.seal"
grep -Fqx "pinned_tar_sha256=$EXPECTED_TAR" "$LOGS/source_identity.tsv"
grep -Fqx "tarball_sha256=$EXPECTED_TAR" "$LOGS/source_identity.tsv"

 # The installed-prefix seal was authenticated and checked above.
(cd "$PREFIX" && sha256sum --strict --quiet -c \
    "$LOGS/installed_prefix.sha256")

TMP=$(mktemp -d /tmp/ed301-openssl-lane-verify.XXXXXX)
cleanup() {
    rm -rf -- "$TMP"
}
trap cleanup EXIT HUP INT TERM
(
    cd "$PREFIX"
    find . -type f -printf '%P\n' | sort >"$TMP/files"
    find . -mindepth 1 -type d -printf '%P\n' | sort >"$TMP/directories"
    find . -type l -printf '%P\t%l\n' | sort >"$TMP/symlinks"
    find . -mindepth 1 ! -type d ! -type f ! -type l -print \
        >"$TMP/special"
)
cmp -s "$LOGS/installed_prefix_files.lst" "$TMP/files"
cmp -s "$LOGS/installed_prefix_directories.lst" "$TMP/directories"
cmp -s "$LOGS/installed_prefix_symlinks.tsv" "$TMP/symlinks"
test ! -s "$TMP/special"

while IFS="$(printf '\t')" read -r link target; do
    test -n "$link" && test -n "$target"
    case "$target" in /*) exit 1 ;; esac
    canonical=$(readlink -f -- "$PREFIX/$link")
    case "$canonical" in "$PREFIX"/*) ;; *) exit 1 ;; esac
done <"$LOGS/installed_prefix_symlinks.tsv"

test -x "$PREFIX/bin/openssl"
test -d "$PREFIX/include/openssl"
test -d "$PREFIX/lib"
printf 'openssl_lane_verification=PASS version=%s prefix=%s evidence=%s\n' \
    "$VERSION" "$PREFIX" "$EXPECTED"
