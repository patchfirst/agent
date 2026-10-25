#!/bin/sh
export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
sec() { printf '\n@@%s\n' "$1"; }
has() { command -v "$1" >/dev/null 2>&1; }
t() { timeout 10 "$@" 2>&1 | head -3; }

rpm_packages() {
  has rpm || return
  rpm_format='%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\t%{VENDOR}'
  # Older/non-modular rpm builds may not know MODULARITYLABEL at all.
  if rpm --querytags 2>/dev/null | grep -qx MODULARITYLABEL; then
    rpm_format="$rpm_format"'\t%{MODULARITYLABEL}'
  fi
  rpm -qa --qf "$rpm_format"'\n' 2>/dev/null
}

apt_origin_parse() {
  # The first input maps repository indexes to their signed Release origin.
  # Output: name and class. "local": no configured repository knows the name
  # (an outdated distro version still lists its newer versions).
  awk '
    FNR==NR {
      if ($2 ~ /^(https?|file):/) index_key=$2 " " $3
      if ($1=="release" && index_key!="") {
        origins[index_key] = ($0 ~ /(^|[ ,])o=(Debian|Ubuntu|UbuntuESMApps|UbuntuESM)(,|$)/ ? "distro" : "third_party")
        index_key=""
      }
      next
    }
    function emit() {
      if (name!="") print name "\t" (!known ? "local" : distro && !third ? "distro" : third && !distro ? "third_party" : "unknown")
    }
    /^[^[:space:]].*:$/ {emit(); name=$0; sub(/:$/, "", name); distro=third=active=known=0; next}
    $2 ~ /^(https?|file):/ {known=1}
    $1=="***" {active=1; next}
    $2 ~ /^[0-9]+$/ && $1!="***" {active=0}
    active && $2 ~ /^(https?|file):/ {
      origin=origins[$2 " " $3]
      if (origin=="distro") distro=1
      if (origin=="third_party") third=1
    }
    END {emit()}' "$1" "$2"
}

apt_package_origins() {
  has apt-cache && has dpkg-query || return
  origin_dir=$(mktemp -d "${TMPDIR:-/tmp}/psr-origin.XXXXXX") || return
  if has timeout; then
    timeout 15 apt-cache policy >"$origin_dir/indexes" 2>/dev/null
    dpkg-query -W -f='${Package}\n' 2>/dev/null | xargs -r timeout 15 apt-cache policy >"$origin_dir/packages" 2>/dev/null
  else
    # Without a deadline, skip this optional provenance probe.
    rm -rf "$origin_dir"
    return
  fi
  apt_origin_parse "$origin_dir/indexes" "$origin_dir/packages"
  rm -rf "$origin_dir"
}

composer_paths() {
  count=0
  while IFS= read -r f; do
    case "$f" in *"$(printf '\t')"*|*'\'*)
      [ -z "$scan_dir" ] || echo skipped >>"$scan_dir/skipped"
      continue ;;
    esac
    [ -f "$f" ] || [ -d "$f" ] || {
      [ -z "$scan_dir" ] || echo skipped >>"$scan_dir/skipped"
      continue
    }
    case "$f" in */vendor/*|*/node_modules/*|*/.git/*|*/.vscode-server/*|*/.cursor-server/*) continue ;; esac
    case "$f" in
      */releases/*)
        base=${f%%/releases/*}
        release=${f#"$base/releases/"}
        case "$release" in
          */*)
            release=${release%%/*}
            releases_base=$(readlink -f "$base/releases" 2>/dev/null)
            current=$(readlink -f "$base/current" 2>/dev/null)
            case "$current" in
              "$releases_base/"*)
                active=${current#"$releases_base/"}
                active=${active%%/*}
                [ -e "$base/current" ] && [ "$active" != "$release" ] && continue ;;
            esac ;;
        esac
        ;;
    esac
    printf '%s\n' "$f"
  done
}

composer_read() {
  head -n 100 | while IFS= read -r f; do
    [ -f "$f" ] || continue
    # Walk the JSON: packages are the objects of the "packages"/"packages-dev" arrays.
    # Packagist marks its packages with its download notification URL; anything else is a private repository.
    awk -v f="$f" '
      function flush() {
        if (name != "" && version != "") {
          print "composer\t" f "\t" name "\t" version "\t" dev
          if (url == "https://packagist.org/downloads/") print "composer_public\t" f "\t" name "\t-\t-"
        }
        name = version = url = ""
      }
      function scalar(value) {
        if (depth == 3 && section != "") {
          if (key[3] == "name") name = value
          else if (key[3] == "version") version = value
          else if (key[3] == "notification-url") url = value
        }
      }
      {
        n = length($0)
        for (i = 1; i <= n; i++) {
          c = substr($0, i, 1)
          if (instring) {
            if (escaped) { escaped = 0; text = text c; continue }
            if (c == "\\") { escaped = 1; continue }
            if (c != "\"") { text = text c; continue }
            instring = 0
            if (expectkey) key[depth] = text; else scalar(text)
            continue
          }
          if (c == "\"") { instring = 1; text = ""; continue }
          if (c == "{") { kind[++depth] = "o"; expectkey = 1; key[depth] = ""; if (depth == 3 && section != "") flush(); continue }
          if (c == "[") {
            kind[++depth] = "a"; expectkey = 0
            if (depth == 2 && key[1] == "packages") { section = "p"; dev = 0 }
            if (depth == 2 && key[1] == "packages-dev") { section = "d"; dev = 1 }
            continue
          }
          if (c == "}") { if (depth == 3 && section != "") flush(); depth--; expectkey = 0; continue }
          if (c == "]") { if (depth == 2) section = ""; depth--; expectkey = 0; continue }
          if (c == ",") { expectkey = (kind[depth] == "o"); continue }
          if (c == ":") { expectkey = 0; continue }
        }
      }' "$f"
  done
}

pip_index_config() {
  [ -r "$1" ] || return
  awk '
    /^[[:space:]]*[#;]/ {next}
    /^[[:space:]]*\[/ {section=tolower($0); next}
    section ~ /^\[(global|install)\]/ && /^[[:space:]]*index[-_]url[[:space:]]*=/ {
      sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]+$/, ""); print
    }' "$1"
}

pip_primary_private() {
  metadata=$1
  owner_uid=$(stat -c %u "$metadata" 2>/dev/null)
  owner_home=$(awk -F: -v uid="$owner_uid" '$3==uid {print $6; exit}' /etc/passwd 2>/dev/null)
  # pip precedence: global, user, virtualenv, PIP_CONFIG_FILE, environment.
  index=$(
    if [ "${PIP_CONFIG_FILE:-}" != /dev/null ]; then
    for config in /etc/xdg/pip/pip.conf /etc/pip.conf \
      "$owner_home/.pip/pip.conf" "$owner_home/.config/pip/pip.conf" \
      "$HOME/.pip/pip.conf" "${XDG_CONFIG_HOME:-$HOME/.config}/pip/pip.conf"; do
      pip_index_config "$config"
    done
    parent=${metadata%/*}
    while [ -n "$parent" ] && [ "$parent" != / ]; do
      if [ -r "$parent/pip.conf" ]; then pip_index_config "$parent/pip.conf"; break; fi
      parent=${parent%/*}
    done
    [ -z "${PIP_CONFIG_FILE:-}" ] || pip_index_config "$PIP_CONFIG_FILE"
    fi
  )
  index=$(printf '%s\n' "$index" | tail -n 1)
  [ -z "${PIP_INDEX_URL:-}" ] || index=$PIP_INDEX_URL
  # extra-index-url is not exclusive provenance: packages may come from PyPI.
  case "$index" in ''|https://pypi.org|https://pypi.org/*|https://files.pythonhosted.org/*) return 1 ;; esac
  return 0
}

# Registry files may contain authentication tokens. Read them only on the host;
# the collection protocol carries scope + privacy, never their contents or URLs.
npm_registry_config() {
  [ -r "$1" ] || return 0
  case "$1" in *.yarnrc|*.yarnrc.yml) yarn_registry=1 ;; *) yarn_registry=0 ;; esac
  awk -v yarn="$yarn_registry" '
  function trim(s) {sub(/^[ \t]+/, "", s); sub(/[ \t\r]+$/, "", s); return s}
  function decision(scope, value) {
    value=trim(value); gsub(/^["\047]|["\047]$/, "", value)
    value=tolower(value)
    public=(value ~ /^https:\/\/registry[.]npmjs[.]org(:443)?(\/|$)/)
    if (yarn && value ~ /^https:\/\/registry[.]yarnpkg[.]com(:443)?(\/|$)/) public=1
    print scope "\t" (public ? "public" : "private")
  }
  {
    line=$0; sub(/[ \t]+#.*/, "", line)
    if (line ~ /^[ \t]*["\047](@[a-zA-Z0-9_.~-]+:)?registry["\047][ \t]/) {
      sub(/^[ \t]*["\047]/, "", line); sub(/["\047][ \t]/, " ", line)
    }
    if (line ~ /^[ \t]*#/ || line ~ /^[ \t]*$/) next
    if (line ~ /^[^ \t]/) {scopes=(line ~ /^npmScopes:[ \t]*$/); scope=""}
    if (scopes && line ~ /^[ \t]+["\047]?@?[a-zA-Z0-9_.~-]+["\047]?:[ \t]*$/) {
      scope=trim(line); sub(/:[ \t]*$/, "", scope); gsub(/["\047]/, "", scope); sub(/^@/, "", scope); scope="@" tolower(scope)
    }
    if (line ~ /^[ \t]*npmRegistryServer[ \t]*:/) {
      value=line; sub(/^[ \t]*npmRegistryServer[ \t]*:[ \t]*/, "", value)
      decision(scopes && scope!="" ? scope : "*", value)
    } else if (tolower(line) ~ /^[ \t]*(@[a-z0-9_.~-]+:)?registry[ \t]*(=|[ \t])/) {
      key=line; sub(/^[ \t]*/, "", key); sub(/[= \t].*$/, "", key); key=tolower(key)
      value=line; sub(/^[ \t]*[^= \t]+[ \t]*[= \t][ \t]*/, "", value)
      scope="*"; if (key ~ /^@/) {scope=key; sub(/:registry$/, "", scope)}
      decision(tolower(scope), value)
    }
  }' "$1"
}

npm_registry_flags() {
  npm_lock=$1
  npm_owner=$(stat -c %u "$npm_lock" 2>/dev/null)
  npm_owner_home=$(awk -F: -v uid="$npm_owner" '$3==uid {print $6; exit}' /etc/passwd)
  npm_node=$(command -v node 2>/dev/null)
  npm_node=$(readlink -f "$npm_node" 2>/dev/null)
  case "$npm_node" in */bin/node) npm_install_prefix=${npm_node%/bin/node} ;; *) npm_install_prefix= ;; esac
  {
    npm_registry_config /etc/npmrc
    for npm_prefix in /usr /usr/local "$npm_install_prefix" "${PREFIX:-}" "${npm_config_prefix:-}" "${NPM_CONFIG_PREFIX:-}"; do
      [ -z "$npm_prefix" ] || npm_registry_config "$npm_prefix/etc/npmrc"
    done
    npm_globalconfig=${npm_config_globalconfig:-${NPM_CONFIG_GLOBALCONFIG:-}}
    [ -z "$npm_globalconfig" ] || npm_registry_config "$npm_globalconfig"
    # The collecting account and the account owning the lock may differ (sudo).
    for npm_home in /root "${HOME:-}" "$npm_owner_home"; do
      [ -z "$npm_home" ] && continue
      npm_registry_config "$npm_home/.npmrc"
      npm_registry_config "$npm_home/.yarnrc"
      npm_registry_config "$npm_home/.yarnrc.yml"
    done
    npm_userconfig=${npm_config_userconfig:-${NPM_CONFIG_USERCONFIG:-}}
    [ -z "$npm_userconfig" ] || npm_registry_config "$npm_userconfig"
    # Apply ancestor configs from / down to the project, preserving overrides.
    npm_dir=${npm_lock%/*}
    npm_ancestors=
    while [ -n "$npm_dir" ] && [ "$npm_dir" != / ]; do
      npm_ancestors="$npm_dir
$npm_ancestors"
      npm_dir=${npm_dir%/*}
    done
    printf '%s\n' "$npm_ancestors" | while IFS= read -r npm_dir; do
      [ -z "$npm_dir" ] && continue
      npm_registry_config "$npm_dir/.npmrc"
      npm_registry_config "$npm_dir/.yarnrc"
      npm_registry_config "$npm_dir/.yarnrc.yml"
    done
    {
      # Some POSIX shells drop inherited keys containing @/: before `env`.
      # Linux keeps the original process environment, including npm scope keys.
      [ ! -r "/proc/$$/environ" ] || tr '\000' '\n' <"/proc/$$/environ"
      env
    } | awk '
      { key=$0; sub(/=.*/, "", key); key=tolower(key)
        if (key !~ /^npm_config_(@[a-z0-9_.~-]+:)?registry$/) next
        scope=key; sub(/^npm_config_/, "", scope); sub(/:registry$/, "", scope)
        if (scope=="registry") scope="*"
        value=$0; sub(/^[^=]*=/, "", value); value=tolower(value)
        public=(value ~ /^https:\/\/registry[.]npmjs[.]org(:443)?(\/|$)/)
        print scope "\t" (public ? "public" : "private")
      }'
  } | awk -F '\t' -v lock="$npm_lock" '{rules[$1]=$2} END {for (scope in rules) print lock "\t" scope "\t" rules[scope]}'
}

deps_read() {
  files=0
  bytes=0
  while IFS= read -r f; do
    case "$f" in
      */.npmrc|*/.yarnrc|*/.yarnrc.yml) continue ;;
      */package-lock.json|*/yarn.lock|*/pnpm-lock.yaml)
        npm_registry_flags "$f" >>"$scan_dir/npm_registry" ;;
    esac
    [ -r "$f" ] || { echo skipped >>"$scan_dir/deps_flags"; continue; }
    files=$((files + 1))
    if [ "$files" -gt 1000 ]; then echo limited >>"$scan_dir/deps_flags"; break; fi
    case "$f" in
      */METADATA)
        # The description after the headers may contain arbitrary Name:/Version: entries.
        awk '/^\r?$/{exit} /^Name: |^Version: /{sub(/\r$/, ""); print}' "$f" >"$scan_dir/deps_content"
        # PEP 610 is inspected locally; paths, repository names and credentials stay here.
        direct=${f%/*}/direct_url.json
        if [ -r "$direct" ] && head -c 65536 "$direct" | tr '\n\r' '  ' | \
          grep -Eq '"url"[[:space:]]*:[[:space:]]*"file:|"vcs_info"[[:space:]]*:|"editable"[[:space:]]*:[[:space:]]*true'; then
          printf 'PSR-Private: direct\n' >>"$scan_dir/deps_content"
        fi
        pip_root=${f%/*.dist-info/METADATA}
        if [ "${pip_cached_root:-}" != "$pip_root" ]; then
          pip_cached_root=$pip_root
          pip_cached_private=
          pip_primary_private "$f" && pip_cached_private=1
        fi
        [ -z "$pip_cached_private" ] || printf 'PSR-Private: index\n' >>"$scan_dir/deps_content"
        source_file=$scan_dir/deps_content
        size=$(wc -c <"$source_file") ;;
      *) source_file=$f; size=$(wc -c <"$f") ;;
    esac
    if [ "$size" -gt 2097152 ] || [ "$((bytes + size))" -gt 16777216 ]; then
      echo limited >>"$scan_dir/deps_flags"
      continue
    fi
    encoded=$(base64 <"$source_file" | tr -d '\n')
    bytes=$((bytes + size))
    printf '%s\t%s\n' "$f" "$encoded"
  done
}

composer_scan() {
  scan_dir=$(mktemp -d) || {
    sec composer
    for root do
      for f in "$root"/composer.lock "$root"/*/composer.lock "$root"/*/*/composer.lock; do
        printf '%s\n' "$f"
      done
    done | composer_paths | composer_read
    sec composer_scan
    echo skipped
    sec deps_scan
    echo skipped
    return
  }
  scan_started=$(date +%s)
  # find -xdev does not traverse separate filesystems under root.
  for root do
    [ -r /proc/self/mountinfo ] || continue
    resolved_root=$(readlink -f "$root")
    awk -v root="$resolved_root/" 'index($5,root)==1 {print $5}' /proc/self/mountinfo |
    while IFS= read -r mount; do
      [ "$(stat -c %d "$root" 2>/dev/null)" = "$(stat -c %d "$mount" 2>/dev/null)" ] || echo skipped >>"$scan_dir/skipped"
    done
  done
  # find passes the entire path as an argument: a newline must not be parsed as two paths.
  safe_find_paths='flags=$1; shift
for path do
  case "$path" in *"
"*) echo skipped >>"$flags" ;; *) printf "%s\n" "$path" ;; esac
done'
  set -- find -H "$@" -xdev -maxdepth 6 \( \
    -type d \( -name vendor -o -name node_modules -o -name .git -o -name .vscode-server -o -name .cursor-server \) -prune \) -o \( \
    \( -type d \( -name .venv -o -name venv -o -name site-packages \) -prune \) -o \( \
    -type f \( -name composer.lock -o -name package-lock.json -o -name package.json -o -name yarn.lock -o -name pnpm-lock.yaml \
    -o -name poetry.lock -o -name Pipfile.lock -o -name uv.lock -o -name 'requirements*.txt' \) \) \) \
    -exec sh -c "$safe_find_paths" sh "$scan_dir/skipped" {} +
  if has timeout; then
    set -- timeout "${COMPOSER_SCAN_SECONDS:-15}" "$@"
  fi
  {
    "$@" 2>/dev/null
    echo $? >"$scan_dir/rc"
  } | composer_paths >"$scan_dir/paths"
  case "$(cat "$scan_dir/rc")" in 0|124|143) ;; *) echo skipped >>"$scan_dir/skipped" ;; esac
  : >"$scan_dir/locks"
  : >"$scan_dir/deps"
  : >"$scan_dir/manifests"
  : >"$scan_dir/envs"
  while IFS= read -r f; do
    case "$f" in
      */composer.lock) printf '%s\n' "$f" >>"$scan_dir/locks" ;;
      */package.json) printf '%s\n' "$f" >>"$scan_dir/manifests" ;;
      *) if [ -d "$f" ]; then printf '%s\n' "$f" >>"$scan_dir/envs"; else printf '%s\n' "$f" >>"$scan_dir/deps"; fi ;;
    esac
  done <"$scan_dir/paths"
  sec composer_scan
  [ "$(wc -l <"$scan_dir/locks")" -gt 100 ] && echo limited
  [ ! -s "$scan_dir/skipped" ] || echo skipped
  case "$(cat "$scan_dir/rc")" in 124|143) echo timeout ;; esac
  sec composer
  composer_read <"$scan_dir/locks"
  [ "$(wc -l <"$scan_dir/deps")" -le 100 ] || echo limited >>"$scan_dir/deps_flags"
  head -n 100 "$scan_dir/deps" >"$scan_dir/deps_read"
  # Discovery manifests have their own budget and cannot displace lockfiles.
  [ "$(wc -l <"$scan_dir/manifests")" -le 100 ] || echo limited >>"$scan_dir/deps_flags"
  head -n 100 "$scan_dir/manifests" >>"$scan_dir/deps_read"
  head -n 100 "$scan_dir/deps" | while IFS= read -r f; do
    case "$f" in
      */yarn.lock|*/pnpm-lock.yaml)
        manifest=${f%/*}/package.json
        if [ -r "$manifest" ]; then printf '%s\n' "$manifest"; fi ;;
    esac
  done >>"$scan_dir/deps_read"
  count=0
  while IFS= read -r env; do
    count=$((count + 1))
    [ "$count" -le 100 ] || { echo limited >>"$scan_dir/deps_flags"; break; }
    remaining=$((${COMPOSER_SCAN_SECONDS:-15} - $(date +%s) + scan_started))
    if [ "$remaining" -le 0 ]; then echo timeout >>"$scan_dir/deps_flags"; break; fi
    if has timeout; then
      timeout "$remaining" find "$env" -xdev -maxdepth 6 -type f -path '*.dist-info/METADATA' \
        -exec sh -c "$safe_find_paths" sh "$scan_dir/skipped" {} + 2>/dev/null >"$scan_dir/metadata"
      case "$?" in 0) ;; 124|143) echo timeout >>"$scan_dir/deps_flags" ;; *) echo skipped >>"$scan_dir/deps_flags" ;; esac
    else
      find "$env" -xdev -maxdepth 6 -type f -path '*.dist-info/METADATA' \
        -exec sh -c "$safe_find_paths" sh "$scan_dir/skipped" {} + 2>/dev/null >"$scan_dir/metadata"
    fi
    head -n 1001 "$scan_dir/metadata" | composer_paths >>"$scan_dir/deps_read"
    [ "$(wc -l <"$scan_dir/metadata")" -le 1000 ] || echo limited >>"$scan_dir/deps_flags"
  done <"$scan_dir/envs"
  sec deps_files
  deps_read <"$scan_dir/deps_read"
  sec deps_registry
  [ ! -f "$scan_dir/npm_registry" ] || cat "$scan_dir/npm_registry"
  sec deps_scan
  [ ! -s "$scan_dir/deps_flags" ] || sort -u "$scan_dir/deps_flags"
  [ ! -s "$scan_dir/skipped" ] || echo skipped
  case "$(cat "$scan_dir/rc")" in 124|143) echo timeout ;; esac
  rm -rf "$scan_dir"
}

sec os
cat /etc/os-release 2>/dev/null

sec kernel
uname -r

sec reboot
[ -f /var/run/reboot-required ] && echo required && cat /var/run/reboot-required.pkgs 2>/dev/null

sec dpkg
has dpkg-query && dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\t${source:Package}\t${source:Version}\t${Maintainer}\n' 2>/dev/null | awk -F'\t' '$1 ~ /^ii/ {print $2"\t"$3"\t"$4"\t"$5"\t"$6}'

sec rpm
rpm_packages

sec apk
if has apk; then
  # Installed DB records the source origin even for lib*/-dev subpackages.
  awk -F: 'function emit() {if (name && version) print name "\t" version "\t" (origin ? origin : name)}
    /^P:/ {name=$2} /^V:/ {version=$2} /^o:/ {origin=$2}
    /^$/ {emit(); name=version=origin=""} END {emit()}' /lib/apk/db/installed 2>/dev/null
fi

sec package_origins
apt_package_origins

sec upgradable
has apt && apt list --upgradable 2>/dev/null | grep -v '^Listing'

sec listen
# Only the owner's collector needs the port number: for the service type and reachability check.
# ss shows the process name without arguments if the current user has permission.
has ss && ss -tlnpH 2>/dev/null | awk '{
  program=""
  if ($0 ~ /users:\(\("/) {
    program=$0; sub(/^.*users:\(\("/, "", program); sub(/".*/, "", program)
  }
  print $4 "\t" program
}'

sec apache_mods
ls /etc/apache2/mods-enabled/ 2>/dev/null | grep '^php.*\.load$'

sec procs
ps -eo comm=,args= 2>/dev/null | awk '{print $1"\t"$2}' | sort -u

sec procpkg
if has dpkg; then
  ps -eo args= 2>/dev/null | awk '{print $1}' | grep '^/' | sort -u | while read -r p; do [ -e "$p" ] && readlink -f "$p"; done | sort -u | xargs -r dpkg -S 2>/dev/null
fi

sec bins
for b in php php-fpm nginx apache2 httpd haproxy mysqld mariadbd redis-server valkey-server node python3 docker dockerd containerd runc kubelet postgres clickhouse-server zabbix_server zabbix_agent2 java openssl sshd sudo memcached certbot git; do
  p=$(command -v "$b" 2>/dev/null) || continue
  real=$(readlink -f "$p")
  owner=
  has dpkg && owner=$(dpkg -S "$real" 2>/dev/null | head -1 | cut -d: -f1)
  has rpm && [ -z "$owner" ] && owner=$(rpm -qf "$real" 2>/dev/null | grep -v 'not owned' | head -1)
  has apk && [ -z "$owner" ] && owner=$(apk info --who-owns "$real" 2>/dev/null | sed -n 's/.* is owned by //p' | head -1)
  if [ -n "$owner" ]; then v=-; else
    owner=-
    case "$b" in
      php|php-fpm|apache2|httpd) v=$(t "$p" -v | head -1) ;;
      nginx|haproxy) v=$(t "$p" -v | head -1) ;;
      openssl) v=$(t "$p" version) ;;
      java) v=$(t "$p" -version | head -1) ;;
      sshd) v=$(t "$p" -V | head -1) ;;
      *) v=$(t "$p" --version | head -1) ;;
    esac
  fi
  printf '%s\t%s\t%s\t%s\n' "$b" "$real" "$owner" "$v"
done

sec docker
if has docker && timeout 10 docker info >/dev/null 2>&1; then
  docker ps --no-trunc --format '{{.Names}}\t{{.Image}}\t{{.ImageID}}\t{{.Ports}}' 2>/dev/null
  sec images
  docker ps -q 2>/dev/null | xargs -r docker inspect --format '{{.Image}}' 2>/dev/null | sort -u | xargs -r docker image inspect --format '{{.Id}}\t{{join .RepoTags ","}}\t{{join .RepoDigests ","}}\t{{.Created}}' 2>/dev/null
fi

sec apps
for f in /var/www/*/version.php /var/www/*/*/version.php /srv/*/version.php; do
  [ -r "$f" ] && grep -q OC_VersionString "$f" && printf 'nextcloud\t%s\t%s\n' "$f" "$(sed -n "s/.*OC_VersionString = '\([^']*\)'.*/\1/p" "$f")"
done
for f in /home/bitrix/www/bitrix/modules/main/classes/general/version.php /var/www/*/bitrix/modules/main/classes/general/version.php; do
  [ -r "$f" ] && printf 'bitrix\t%s\t%s\n' "$f" "$(sed -n 's/.*"SM_VERSION", *"\([^"]*\)".*/\1/p' "$f")"
done
set --
for root in /var/www /srv /opt /home /data /app /usr/share/nginx /usr/local/www /www; do
  [ -d "$root" ] && set -- "$@" "$root"
done
[ "$#" -eq 0 ] || composer_scan "$@"
true
