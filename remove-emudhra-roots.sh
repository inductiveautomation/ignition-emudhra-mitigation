#!/bin/sh
# SPDX-License-Identifier: MIT
#
# In every Ignition Java runtime on this machine, including the runtimes a
# gateway hands out to Designers and Vision Clients, removes eMudhra's root
# certificates and Sectigo's AAA Certificate Services root from cacerts.
# Run as root. Pass extra install folders as arguments if Ignition or a
# launcher is installed somewhere non-default.
#
#   sudo sh ./remove-emudhra-roots.sh [/path/to/ignition ...]
set -eu

# Added to a gateway's runtime version so clients download the patched runtime
# instead of reusing a cached one. Change it whenever a runtime fixed by an
# earlier version of this script needs changing again, along with the
# PowerShell script and the folder name in README.md's "Check that it
# worked". Digits only: older launchers reject any other character in a version.
RUNTIME_SUFFIX=20261028
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
trap 'exit 1' INT TERM

# A redirect.txt in a user's .ignition folder moves that user's cache to the
# folder on its first line. Read it literally, as the launchers do.
for redirect in /root/.ignition/redirect.txt /home/*/.ignition/redirect.txt \
  /Users/*/.ignition/redirect.txt; do
  [ -f "$redirect" ] || continue
  dir=$(head -n 1 "$redirect" 2>/dev/null | tr -d '\r')
  if [ -n "$dir" ]; then set -- "$@" "$dir"; fi
done

# SHA-256 fingerprints of the roots to remove: the four Oracle lists (see
# https://ops.java/emudhra), emSign ECC Root CA - G3 and AAA Certificate
# Services, which the compromised intermediates chain to, and emSign Root CA -
# G1 and G2; and eMudhra's other two roots, emSign Root CA - C1 and emSign ECC
# Root CA - C3, which only older runtimes have. Removing the roots, rather than
# blocking the compromised intermediates by fingerprint, also stops re-encoded
# copies of them. Roots are matched by fingerprint because older Ignition
# runtimes use different aliases. Older runtimes don't have G2.
ROOTS="86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B
D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4
40F6AF0346A99AA1CD1D555A4E9CCE62C7F9634603EE406615833DC8C8D00367
1AA0C2709E831BD6E3B5129A00BA41F7EEEF020872F1E6504BF0F6C3F24F3AF3
125609AA301DA0A249B97A8239CB6A34216F44DCAC9F3954B14292F2E8C8608F
BC4D809B15189D78DB3E1D8CF4F9726A795DA1643CA5F1358E1DDB0EDC0D7EB3"

# Runs keytool with the java at $1 against the trust store at $2. keytool runs
# through java because a client runtime's keytool isn't marked executable.
# English output keeps the labels root_aliases reads stable.
keytool_on() {
  j=$1
  ks=$2
  shift 2
  "$j" -Duser.language=en -Duser.country=US -m java.base/sun.security.tools.keytool.Main \
    "$@" -keystore "$ks" -storepass changeit
}

# Prints the aliases of our roots in the keytool -list -v output on stdin.
root_aliases() {
  awk -v roots="$(printf '%s' "$ROOTS" | tr '\n' ' ')" '
    BEGIN { n = split(roots, r, " "); for (i = 1; i <= n; i++) ours[r[i]] = 1 }
    /^Alias name: / { alias = substr($0, 13) }
    /^[ \t]*SHA256: / { fp = $2; gsub(":", "", fp); if (fp in ours) print alias }'
}

# Prints the aliases of our roots in the trust store at $2, read with the java
# at $1. Fails if it can't list the store, so an unreadable or empty store never
# passes as one without our roots.
find_roots() {
  list=$(keytool_on "$1" "$2" -list -v 2> /dev/null) &&
    printf '%s\n' "$list" | grep -q '^Alias name: ' &&
    printf '%s\n' "$list" | root_aliases
}

# Deletes the aliases in $3 from the trust store at $2 with the java at $1, then
# checks none of our roots is left.
delete_roots() {
  printf '%s\n' "$3" | while IFS= read -r a; do
    keytool_on "$1" "$2" -delete -alias "$a" > /dev/null 2>&1 || exit 1
  done && left=$(find_roots "$1" "$2") && [ -z "$left" ]
}

# Removes our roots from the cacerts of the runtime at $1, keeping the original
# as cacerts.orig. cacerts is changed in a copy made with cp -p, which keeps its
# owner and permissions, and the copy is renamed over it. Nothing reading it,
# such as a running gateway, ever sees it half-written, even if the script is
# interrupted.
remove_roots() {
  ks=$1/lib/security/cacerts
  [ -f "$ks" ] || return 0
  if ! aliases=$(find_roots "$1/bin/java" "$ks"); then
    echo "failed: $ks (couldn't read it with $1/bin/java)" >&2
    return 1
  fi
  if [ -z "$aliases" ]; then
    echo "roots already removed: $ks"
  elif { [ -e "$ks.orig" ] || cp -p "$ks" "$ks.orig"; } && cp -p "$ks" "$ks.new" &&
    delete_roots "$1/bin/java" "$ks.new" "$aliases" && mv -f "$ks.new" "$ks"; then
    echo "removed roots: $ks"
  else
    rm -f "$ks.new"
    echo "failed: $ks" >&2
    return 1
  fi
}

status=0
for root in \
  /usr/local/bin/ignition /usr/local/ignition \
  /Applications/*Launcher*.app /Applications/*Workstation*.app \
  /root/.ignition /home/*/.ignition /Users/*/.ignition \
  "$@"; do
  [ -d "$root" ] || continue
  # -H follows $root itself if it is a symlink, but not links inside it.
  # Runtimes are found by their cacerts, next to a bin/java. A file that can't
  # be patched is reported and skipped, not fatal, so one locked runtime doesn't
  # leave the rest unpatched.
  find -H "$root" -type f -path '*/lib/security/cacerts' 2>/dev/null | (
    failed=0
    while IFS= read -r ks; do
      rt=${ks%/lib/security/cacerts}
      [ -f "$rt/bin/java" ] || continue
      remove_roots "$rt" || failed=1
    done
    exit "$failed"
  ) || status=1
done

# macOS tar would otherwise add AppleDouble and extended-attribute entries.
tar_create() {
  if [ "$(uname)" = Darwin ]; then
    COPYFILE_DISABLE=1 tar --no-mac-metadata --no-xattrs --no-acls "$@"
  else
    tar "$@"
  fi
}

# Prints the number of entries in the trust store at $2, read with the java at $1.
count_entries() {
  keytool_on "$1" "$2" -list -v 2> /dev/null | grep -c '^Alias name: '
}

# Prints the java of the gateway's own runtime in the lib/runtime folder at $1.
# It edits the cacerts inside the archives, whichever OS they are for.
gateway_java() {
  for j in "$1"/*/bin/java "$1"/*/Contents/Home/bin/java; do
    if [ -x "$j" ] && "$j" -version > /dev/null 2>&1; then
      echo "$j"
      return 0
    fi
  done
  return 1
}

# Sets aliases and entries from the cacerts at $2, taken from the archive at $1.
inspect_runtime() {
  if ! aliases=$(find_roots "$gw_java" "$2") || ! entries=$(count_entries "$gw_java" "$2"); then
    echo "failed: $1 (couldn't read the cacerts inside with $gw_java)" >&2
    return 1
  fi
}

# Checks the cacerts at $1, taken from a patched archive: it lost our roots and
# nothing else.
check_runtime() {
  left=$(find_roots "$gw_java" "$1") && [ -z "$left" ] &&
    [ "$(count_entries "$gw_java" "$1")" -eq $((entries - $(printf '%s' "$aliases" | grep -c '^'))) ]
}

# Replaces the archive at $1 with $2, keeping the original as $1.orig. The new
# archive is written next to the original and renamed over it, so a client
# downloading the archive meanwhile gets either the whole old one or the whole
# new one.
swap_in() {
  { [ -e "$1.orig" ] || cp -p "$1" "$1.orig"; } || return 1
  if cp -p "$1" "$1.new" && cat "$2" > "$1.new" && mv -f "$1.new" "$1"; then
    return 0
  fi
  rm -f "$1.new"
  return 1
}

# Patches the runtime $2 inside the .tar.gz at $1. The archive is unpacked and
# packed again with the same entries in the same order, so links and
# permissions survive.
patch_tgz() {
  ca=$2/lib/security/cacerts
  w=$TMP/w
  rm -rf "$w" && mkdir "$w" || return 1
  if ! tar -tzf "$1" > "$TMP/list" 2> /dev/null || ! tar -xzf "$1" -C "$w" "$ca" 2> /dev/null; then
    echo "failed: $1 (no $ca inside)" >&2
    return 1
  fi
  inspect_runtime "$1" "$w/$ca" || return 1
  if [ -z "$aliases" ]; then
    echo "already patched: $1"
    return 0
  fi
  if rm -rf "$w" && mkdir "$w" && tar -xzf "$1" -C "$w" &&
    delete_roots "$gw_java" "$w/$ca" "$aliases" &&
    (cd "$w" && tar_create -czf "$TMP/new.tar.gz" --no-recursion -T "$TMP/list") &&
    tar -tzf "$TMP/new.tar.gz" | cmp -s - "$TMP/list" &&
    rm -rf "$TMP/c" && mkdir "$TMP/c" && tar -xzf "$TMP/new.tar.gz" -C "$TMP/c" "$ca" &&
    check_runtime "$TMP/c/$ca" &&
    swap_in "$1" "$TMP/new.tar.gz"; then
    echo "patched: $1"
  else
    echo "failed: $1" >&2
    return 1
  fi
}

# Patches the runtime $2 inside the .zip at $1, replacing only the entries that
# change so the order of the entries is unchanged.
patch_zip() {
  ca=$2/lib/security/cacerts
  w=$TMP/w
  if ! command -v zip > /dev/null || ! command -v unzip > /dev/null; then
    echo "failed: $1 (needs the zip and unzip commands)" >&2
    return 1
  fi
  rm -rf "$w" && mkdir -p "$w/$2/lib/security" || return 1
  if ! unzip -p "$1" "$ca" > "$w/$ca" 2> /dev/null; then
    echo "failed: $1 (no $ca inside)" >&2
    return 1
  fi
  inspect_runtime "$1" "$w/$ca" || return 1
  if [ -z "$aliases" ]; then
    echo "already patched: $1"
    return 0
  fi
  if delete_roots "$gw_java" "$w/$ca" "$aliases" && cp "$1" "$TMP/new.zip" &&
    (cd "$w" && zip -q "$TMP/new.zip" "$ca") &&
    unzip -tqq "$TMP/new.zip" && [ "$(unzip -Z1 "$TMP/new.zip")" = "$(unzip -Z1 "$1")" ] &&
    rm -rf "$TMP/c" && mkdir -p "$TMP/c/$2/lib/security" &&
    unzip -p "$TMP/new.zip" "$ca" > "$TMP/c/$ca" &&
    check_runtime "$TMP/c/$ca" &&
    swap_in "$1" "$TMP/new.zip"; then
    echo "patched: $1"
  else
    echo "failed: $1" >&2
    return 1
  fi
}

# Adds RUNTIME_SUFFIX to the version in $1/version, keeping the original as
# version.orig, and sets base and new to the two versions. The base version
# always comes from version.orig once it exists, so a rerun or a new suffix
# never stacks suffixes.
set_runtime_version() {
  v=$1/version
  if [ -e "$v.orig" ]; then base=$(head -n 1 "$v.orig"); else base=$(head -n 1 "$v"); fi
  base=$(printf '%s' "$base" | tr -d '\r')
  case $base in
    '' | *[!0-9.]*)
      echo "failed: $v (unexpected version '$base')" >&2
      return 1
      ;;
  esac
  new=$base.$RUNTIME_SUFFIX
  if [ "$(head -n 1 "$v" | tr -d '\r')" = "$new" ]; then
    echo "runtime version already $new: $v"
  elif { [ -e "$v.orig" ] || cp -p "$v" "$v.orig"; } && cp -p "$v" "$v.new" &&
    printf '%s' "$new" > "$v.new" && mv -f "$v.new" "$v"; then
    echo "runtime version set to $new: $v"
  else
    rm -f "$v.new"
    echo "failed: $v" >&2
    return 1
  fi
}

# Writes the new version from set_runtime_version into the gateway's own
# runtime folder in $1 as well. A gateway reinstalls that folder from its
# archive when its version differs from lib/runtime/version, which would drop
# changes made inside it, such as certificates added to its cacerts, and the
# .orig files. The folder is only marked when it was at the archives' version,
# or at a version an earlier run of this script set, and its cacerts is already
# fixed. Otherwise, such as right after an upgrade the
# gateway hasn't started from yet, the gateway reinstalls it from the patched
# archive.
mark_runtimes() {
  rc=0
  for d in "$1"/*; do
    if [ ! -d "$d" ] || [ -L "$d" ] || [ ! -f "$d/version" ]; then
      continue
    fi
    cur=$(head -n 1 "$d/version" | tr -d '\r')
    if [ "$cur" = "$new" ]; then
      echo "runtime version already $new: $d/version"
      continue
    fi
    case $cur in
      "$base" | "$base".[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ok=1 ;;
      *) ok=0 ;;
    esac
    if [ "$ok" -eq 0 ] || ! left=$(find_roots "$d/bin/java" "$d/lib/security/cacerts") ||
      [ -n "$left" ]; then
      echo "left for the gateway to reinstall from its patched archive: $d"
      continue
    fi
    if { [ -e "$d/version.orig" ] || cp -p "$d/version" "$d/version.orig"; } &&
      cp -p "$d/version" "$d/version.new" && printf '%s' "$new" > "$d/version.new" &&
      mv -f "$d/version.new" "$d/version"; then
      echo "runtime version set to $new: $d/version"
    else
      rm -f "$d/version.new"
      echo "failed: $d/version" >&2
      rc=1
    fi
  done
  return "$rc"
}

# A gateway hands Designers and Vision Clients the runtimes in
# lib/runtime/jre-*.tar.gz and jre-*.zip, and they cache each one under the
# version in lib/runtime/version. Patch every archive, then change the version
# so clients download the patched runtime. The version only changes once every
# archive is patched: a gateway reinstalls its own runtime from its archive
# when the version changes, unless mark_runtimes marked it, and would get the
# roots back from an unpatched one.
for root in /usr/local/bin/ignition /usr/local/ignition "$@"; do
  [ -d "$root" ] || continue
  find -H "$root" -type f -path '*/lib/runtime/version' 2>/dev/null | (
    failed=0
    while IFS= read -r v; do
      rt=${v%/version}
      archives=0
      archives_ok=1
      gw_java=
      for a in "$rt"/jre-*.tar.gz "$rt"/jre-*.zip; do
        [ -f "$a" ] || continue
        archives=$((archives + 1))
        if [ -z "$gw_java" ] && ! gw_java=$(gateway_java "$rt"); then
          echo "failed: $a (no Java runtime in $rt to edit the cacerts inside with)" >&2
          archives_ok=0
          continue
        fi
        top=$(basename "$a")
        case $a in
          *.zip) patch_zip "$a" "${top%.zip}" || archives_ok=0 ;;
          *) patch_tgz "$a" "${top%.tar.gz}" || archives_ok=0 ;;
        esac
      done
      if [ "$archives" -eq 0 ]; then
        continue
      elif [ "$archives_ok" -eq 1 ]; then
        if set_runtime_version "$rt"; then
          mark_runtimes "$rt" || failed=1
        else
          failed=1
        fi
      else
        echo "failed: $v (left unchanged because a runtime above wasn't patched)" >&2
        failed=1
      fi
    done
    exit "$failed"
  ) || status=1
done

if [ "$status" -ne 0 ]; then
  echo "Some runtimes were not patched; see the failed lines above." >&2
fi
exit "$status"
