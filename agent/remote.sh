#!/bin/sh
export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
sec() { printf '\n@@%s%s\n' "${PSR_SECTION:+$PSR_SECTION:}" "$1"; }
has() { command -v "$1" >/dev/null 2>&1; }
# Files under owners' directories are read only through head_of or bounded: a FIFO, /dev/zero,
# /proc/kmsg or a sparse terabyte must neither hang nor exhaust the root agent.
read_deadline=
if timeout 5 true >/dev/null 2>&1; then read_deadline='timeout 5'
elif timeout -t 5 true >/dev/null 2>&1; then read_deadline='timeout -t 5'; fi
# The first bytes of a regular non-empty file (procfs reports size 0; sysfs and devices are never read).
head_of() {
  [ -f "$1" ] && [ -s "$1" ] && [ -r "$1" ] || return 1
  case "$(readlink -f "$1" 2>/dev/null)" in /proc/*|/sys/*|/dev/*) return 2 ;; esac
  $read_deadline head -c "$2" "$1" 2>/dev/null
}
# A whole file: 1 when absent or unreadable, 2 when larger than the limit (callers flag or assume private).
bounded() {
  [ -f "$1" ] && [ -s "$1" ] && [ -r "$1" ] || return 1
  [ "$(stat -L -c %s "$1" 2>/dev/null)" -le "$2" ] 2>/dev/null || return 2
  head_of "$1" "$2"
}
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
    END {emit()}' "$1" "$2"  # agent-written apt-cache output
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
  composer_bytes=0
  head -n 100 | while IFS= read -r f; do
    [ -f "$f" ] || continue
    # The locks share one 16 MB budget, as dependency files do: a hundred planted 8 MB locks cannot stall the scan.
    composer_bytes=$((composer_bytes + $(stat -L -c %s "$f" 2>/dev/null || echo 0)))
    [ "$composer_bytes" -le 16777216 ] || { [ -z "$scan_dir" ] || echo skipped >>"$scan_dir/skipped"; break; }
    # Walk the JSON: packages are the objects of the "packages"/"packages-dev" arrays.
    # Packagist marks its packages with its download notification URL; anything else is a private repository.
    composer_lock=$(bounded "$f" 8388608) || { [ -z "$scan_dir" ] || echo skipped >>"$scan_dir/skipped"; continue; }
    # BusyBox awk is quadratic in the record length: a one-line lock is cut into 4 KB records.
    # The walk below is per character, so its state carries across the cuts.
    printf '%s\n' "$composer_lock" | if has fold; then fold -b -w 4096; else cat; fi | awk -v f="$f" '
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
            # mawk copies the string on every append: a cap keeps a megabyte string linear.
            if (escaped) { escaped = 0; if (length(text) < 4096) text = text c; continue }
            if (c == "\\") { escaped = 1; continue }
            if (c != "\"") { if (length(text) < 4096) text = text c; continue }
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
      }'
  done
}

# An oversized or unreadable-in-time configuration proves nothing public: it reads as a private index.
pip_index_config() {
  pip_config=$(bounded "$1" 65536) || { [ "$?" -eq 1 ] || echo unknown://oversized; return; }
  printf '%s\n' "$pip_config" | awk '
    /^[[:space:]]*[#;]/ {next}
    /^[[:space:]]*\[/ {section=tolower($0); next}
    section ~ /^\[(global|install)\]/ && /^[[:space:]]*index[-_]url[[:space:]]*=/ {
      sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]+$/, ""); print
    }'
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
  # An unread configuration may hold any scope: no later file can prove the default registry public again.
  npm_config=$(bounded "$1" 65536) || { [ "$?" -eq 1 ] || printf '*\tunknown\n'; return 0; }
  case "$1" in *.yarnrc|*.yarnrc.yml) yarn_registry=1 ;; *) yarn_registry=0 ;; esac
  printf '%s\n' "$npm_config" | awk -v yarn="$yarn_registry" '
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
  }'
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
  } | awk -F '\t' -v lock="$npm_lock" '
    $2 == "unknown" { unknown = 1; next }
    { rules[$1] = $2 }
    END {
      if (unknown) { for (scope in rules) rules[scope] = "private"; rules["*"] = "private" }
      for (scope in rules) print lock "\t" scope "\t" rules[scope]
    }'
}

# Gem homes outside the project roots; distro-owned gem directories are checked as OS packages.
GEM_HOMES='/var/lib/gems/*/specifications
/usr/local/lib/ruby/gems/*/specifications
/usr/local/bundle/specifications
/home/*/.gem/ruby/*/specifications
/home/*/.local/share/gem/ruby/*/specifications
/home/*/.rbenv/versions/*/lib/ruby/gems/*/specifications
/home/*/.rvm/gems/*/specifications
/home/*/.rvm/rubies/*/lib/ruby/gems/*/specifications
/usr/local/rbenv/versions/*/lib/ruby/gems/*/specifications
/usr/local/rvm/gems/*/specifications
/usr/local/rvm/rubies/*/lib/ruby/gems/*/specifications
/opt/rbenv/versions/*/lib/ruby/gems/*/specifications'

# Gemfile.lock paths in; candidate gem homes out: the system ones, vendor/bundle and the configured BUNDLE_PATH.
gem_homes() {
  for d in $GEM_HOMES; do
    [ -d "$d" ] && printf '%s\n' "$d"
  done
  while IFS= read -r f; do
    gem_app=${f%/*}
    bundle_path=$(head_of "$gem_app/.bundle/config" 65536 | sed -n 's/^BUNDLE_PATH:[ \t]*"\{0,1\}\([^"]*\)"\{0,1\}[ \t\r]*$/\1/p' | head -n 1)
    case "$bundle_path" in ''|/*) ;; *) bundle_path=$gem_app/$bundle_path ;; esac
    for d in "$gem_app"/vendor/bundle/ruby/*/specifications ${bundle_path:+"$bundle_path"/ruby/*/specifications}; do
      [ -d "$d" ] && printf '%s\n' "$d"
    done
  done
}

# Candidates in; real gem homes out. A link to a directory of another name is not a gem home.
gem_resolve() {
  while IFS= read -r d; do
    case "$d" in *"$(printf '\t')"*|*'\'*|'') echo skipped >>"$scan_dir/skipped"; continue ;; esac
    real=$(readlink -f "$d") || continue
    case "$real" in */specifications) [ -d "${real%/specifications}/gems" ] && printf '%s\n' "$real" ;; esac
  done
}

# Installed specifications of each gem home, default gems included.
gem_specs() {
  count=0
  while IFS= read -r home; do
    count=$((count + 1))
    [ "$count" -le 100 ] || { echo limited >>"$scan_dir/deps_flags"; break; }
    for dir in "$home" "$home/default"; do
      [ -d "$dir" ] || continue
      # A directory with a million entries is listed only up to the limit, never globbed whole.
      specs=0
      $read_deadline find "$dir" -maxdepth 1 -name '*.gemspec' -type f 2>/dev/null | head -n 1001 | while IFS= read -r f; do
        # A name with a newline splits into fragments outside this directory: they are dropped.
        case "${f#"$dir"/}" in */*|"$f") continue ;; esac
        case "$f" in *"$(printf '\t')"*|*'\'*) echo skipped >>"$scan_dir/skipped"; continue ;; esac
        specs=$((specs + 1))
        [ "$specs" -le 1000 ] || { echo limited >>"$scan_dir/deps_flags"; break; }
        printf '%s\n' "$f"
      done
    done
  done
}

# A Bundler mirror serves rubygems.org from another host while the lock still names rubygems.org.
bundler_mirror() {
  gem_owner_home=$(awk -F: -v uid="$(stat -c %u "$1" 2>/dev/null)" '$3==uid {print $6; exit}' /etc/passwd 2>/dev/null)
  env | grep -q '^BUNDLE_MIRROR__' && return 0
  for config in "${1%/*}/.bundle/config" ${gem_owner_home:+"$gem_owner_home/.bundle/config"} /root/.bundle/config \
    ${HOME:+"$HOME/.bundle/config"} /usr/local/bundle/config; do
    gem_config=$(bounded "$config" 65536) || { [ "$?" -eq 1 ] && continue; return 0; }
    printf '%s\n' "$gem_config" | grep -q '^BUNDLE_MIRROR__' && return 0
  done
  return 1
}

# A lock file over 2 MB is flagged limited; one that is not a regular file or times out, skipped.
lock_read() {
  bounded "$1" 2097152 >"$scan_dir/deps_content" && return 0
  case "$?" in 2) echo limited ;; *) echo skipped ;; esac >>"$scan_dir/deps_flags"
  return 1
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
        head_of "$f" 65536 | awk '/^\r?$/{exit} /^Name: |^Version: /{sub(/\r$/, ""); print}' >"$scan_dir/deps_content"
        # PEP 610 is inspected locally; paths, repository names and credentials stay here.
        direct=${f%/*}/direct_url.json
        if head_of "$direct" 65536 | tr '\n\r' '  ' | \
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
        ;;
      */specifications/*.gemspec|*/specifications/default/*.gemspec)
        [ ! -L "$f" ] || { echo skipped >>"$scan_dir/deps_flags"; continue; }
        # A specification is Ruby code with authors, e-mails and URLs: only the name and version leave the host.
        head_of "$f" 65536 | awk '
          /^# stub: / { if (NF >= 4) { print "Name: " $3; print "Version: " $4; stub = 1; exit } }
          /^[ \t]*s\.name[ \t]*=[ \t]*"/ { name = $0; sub(/^[^"]*"/, "", name); sub(/".*/, "", name) }
          /^[ \t]*s\.version[ \t]*=[ \t]*"/ { version = $0; sub(/^[^"]*"/, "", version); sub(/".*/, "", version) }
          END { if (!stub && name != "" && version != "") { print "Name: " name; print "Version: " version } }
        ' >"$scan_dir/deps_content"
        ;;
      */Gemfile.lock)
        lock_read "$f" || continue
        ! bundler_mirror "$f" || printf '\nPSR-Private: mirror\n' >>"$scan_dir/deps_content"
        ;;
      *)
        lock_read "$f" || continue
        ;;
    esac
    size=$(wc -c <"$scan_dir/deps_content")
    if [ "$size" -gt 2097152 ] || [ "$((bytes + size))" -gt 16777216 ]; then
      echo limited >>"$scan_dir/deps_flags"
      continue
    fi
    encoded=$(base64 <"$scan_dir/deps_content" | tr -d '\n')
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
    -type d \( -name vendor -o -name node_modules -o -name .git -o -name .vscode-server -o -name .cursor-server \
    -o -path '*/bundler/gems' -o \( -name gems -exec sh -c '[ -d "$1/../specifications" ]' sh {} \; \) \) -prune \) -o \( \
    \( -type d \( -name .venv -o -name venv -o -name site-packages \
    -o \( -name specifications -exec sh -c '[ -d "$1/../gems" ]' sh {} \; \) \) -prune \) -o \( \
    -type f \( -name composer.lock -o -name package-lock.json -o -name package.json -o -name yarn.lock -o -name pnpm-lock.yaml \
    -o -name poetry.lock -o -name Pipfile.lock -o -name uv.lock -o -name 'requirements*.txt' -o -name Gemfile.lock \) \) \) \
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
  : >"$scan_dir/gem_homes"
  : >"$scan_dir/gem_found"
  while IFS= read -r f; do
    case "$f" in
      */composer.lock) printf '%s\n' "$f" >>"$scan_dir/locks" ;;
      */package.json) printf '%s\n' "$f" >>"$scan_dir/manifests" ;;
      */specifications) printf '%s\n' "$f" >>"$scan_dir/gem_found" ;;
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
  # System homes and the apps' bundles come first: gem homes planted under /home cannot push them past the limit.
  grep '/Gemfile\.lock$' "$scan_dir/deps" | head -n 100 | gem_homes >>"$scan_dir/gem_homes"
  cat "$scan_dir/gem_found" >>"$scan_dir/gem_homes"
  [ "$(wc -l <"$scan_dir/gem_homes")" -le 200 ] || echo limited >>"$scan_dir/deps_flags"
  head -n 200 "$scan_dir/gem_homes" | gem_resolve | sort -u | gem_specs >>"$scan_dir/deps_read"
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

docker_scan() {
  sec docker
  has docker || return 0
  docker_limit=
  # BusyBox before 1.30 spells it `timeout -t N`; run unbounded there rather than misreport Docker.
  ! timeout 10 true >/dev/null 2>&1 || docker_limit='timeout 30'
  if $docker_limit docker info >/dev/null 2>&1; then
    if docker_rows=$($docker_limit docker ps --no-trunc --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}' 2>/dev/null); then
      docker_images=$(printf '%s\n' "$docker_rows" | cut -f1 | xargs -r $docker_limit docker inspect --format '{{.Id}}{{"\t"}}{{.Image}}' 2>/dev/null)
      { printf '%s\n' "$docker_images"; echo @; printf '%s\n' "$docker_rows"; } | awk -F'\t' '
        !rows { if ($0 == "@") rows = 1; else image[$1] = $2; next }
        $3 != "" { print $2 "\t" $3 "\t" image[$1] "\t" $4 }'
      sec images
      printf '%s\n' "$docker_images" | cut -f2 | sort -u | xargs -r $docker_limit docker image inspect --format '{{.Id}}{{"\t"}}{{range $i, $v := .RepoTags}}{{if $i}},{{end}}{{$v}}{{end}}{{"\t"}}{{range $i, $v := .RepoDigests}}{{if $i}},{{end}}{{$v}}{{end}}{{"\t"}}{{.Created}}' 2>/dev/null
      return 0
    fi
  elif [ ! -S /var/run/docker.sock ]; then
    return 0
  fi
  sec docker_scan
  echo skipped
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
  ps -eo args= 2>/dev/null | awk '{print $1}' | grep '^/' | sort -u | while read -r p; do [ -e "$p" ] && readlink -f "$p"; done | sort -u | tr '\n' '\0' | xargs -0 -r dpkg -S 2>/dev/null
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

docker_scan

sec apps
for f in /var/www/*/version.php /var/www/*/*/version.php /srv/*/version.php; do
  v=$(head_of "$f" 65536 | sed -n "s/.*OC_VersionString = '\([^']*\)'.*/\1/p")
  [ -z "$v" ] || printf 'nextcloud\t%s\t%s\n' "$f" "$v"
done
for f in /home/bitrix/www/bitrix/modules/main/classes/general/version.php /var/www/*/bitrix/modules/main/classes/general/version.php; do
  [ -f "$f" ] && printf 'bitrix\t%s\t%s\n' "$f" "$(head_of "$f" 65536 | sed -n 's/.*"SM_VERSION", *"\([^"]*\)".*/\1/p')"
done
set --
for root in /var/www /srv /opt /home /data /app /usr/share/nginx /usr/local/www /www; do
  [ -d "$root" ] && set -- "$@" "$root"
done
[ "$#" -eq 0 ] || composer_scan "$@"
true
