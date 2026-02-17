#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_SCRIPT="${SCRIPT_DIR}/organize_apps.py"
DEFAULT_TARGET="$(pwd)"
TARGET_DIR="${DEFAULT_TARGET}"
MODE="organize"

APPLY=0
VERBOSE=0
INCLUDE_HIDDEN=0
NORMALIZE_EDITIONS=0
NORMALIZE_PUBLISHERS=0
REFINE_CONTAINERS=0
PROMOTE_UNKNOWN=0

UNKNOWN_DIR="_Unsorted"
NO_VERSION_LABEL="unknown"
ALIASES_FILE=""
PUBLISHERS_FILE="${SCRIPT_DIR}/publishers.json"

if ! command -v dialog >/dev/null 2>&1; then
  echo "ERROR: 'dialog' is required. Install it first (e.g. brew install dialog)." >&2
  exit 1
fi

if [[ ! -f "${PY_SCRIPT}" ]]; then
  echo "ERROR: Python script not found: ${PY_SCRIPT}" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required." >&2
  exit 1
fi

run_dialog() {
  local output
  output="$("$@" 2>&1 >/dev/tty)" || return 1
  printf "%s" "${output}"
}

flag_state() {
  if (( "$1" )); then
    printf "on"
  else
    printf "off"
  fi
}

pick_target_dir() {
  local picked
  picked="$(run_dialog dialog --title "Select target directory" --dselect "${TARGET_DIR}/" 20 90)" || return 1
  if [[ -n "${picked}" ]]; then
    TARGET_DIR="${picked%/}"
  fi
}

pick_mode() {
  local mode
  mode="$(run_dialog dialog --title "Mode" --menu "Choose operation mode" 18 90 8 \
    organize "Default organize mode" \
    rebucket "Rebalance entries into *_checked buckets" \
    audit "Read-only maintenance report" \
    promote_unknown "Promote parseable entries from unknown tracks" \
    refine_containers "Flatten redundant wrapper level in grouped containers" \
    maintain "Promote unknown + refine containers")" || return 1
  MODE="${mode}"
}

configure_flags() {
  local checks
  checks="$(run_dialog dialog --title "Boolean options" --checklist "Enable/disable options" 22 100 14 \
    apply "Perform real moves (--apply)" "$(flag_state "${APPLY}")" \
    verbose "Show SKIP diagnostics (--verbose)" "$(flag_state "${VERBOSE}")" \
    include_hidden "Include hidden entries (--include-hidden)" "$(flag_state "${INCLUDE_HIDDEN}")" \
    normalize_editions "Normalize editions (--normalize-editions)" "$(flag_state "${NORMALIZE_EDITIONS}")" \
    normalize_publishers "Normalize publishers (--normalize-publishers)" "$(flag_state "${NORMALIZE_PUBLISHERS}")" \
    refine_containers "Flatten wrappers (--refine-containers)" "$(flag_state "${REFINE_CONTAINERS}")" \
    promote_unknown "Promote parseable unknown entries (--promote-unknown)" "$(flag_state "${PROMOTE_UNKNOWN}")")" || return 1

  APPLY=0
  VERBOSE=0
  INCLUDE_HIDDEN=0
  NORMALIZE_EDITIONS=0
  NORMALIZE_PUBLISHERS=0
  REFINE_CONTAINERS=0
  PROMOTE_UNKNOWN=0

  [[ "${checks}" == *"apply"* ]] && APPLY=1
  [[ "${checks}" == *"verbose"* ]] && VERBOSE=1
  [[ "${checks}" == *"include_hidden"* ]] && INCLUDE_HIDDEN=1
  [[ "${checks}" == *"normalize_editions"* ]] && NORMALIZE_EDITIONS=1
  [[ "${checks}" == *"normalize_publishers"* ]] && NORMALIZE_PUBLISHERS=1
  [[ "${checks}" == *"refine_containers"* ]] && REFINE_CONTAINERS=1
  [[ "${checks}" == *"promote_unknown"* ]] && PROMOTE_UNKNOWN=1
}

configure_values() {
  local v
  v="$(run_dialog dialog --title "unknown-dir" --inputbox "Folder for unparsed entries (--unknown-dir)" 10 90 "${UNKNOWN_DIR}")" || return 1
  UNKNOWN_DIR="${v}"

  v="$(run_dialog dialog --title "no-version-label" --inputbox "Label for names without version (--no-version-label)" 10 90 "${NO_VERSION_LABEL}")" || return 1
  NO_VERSION_LABEL="${v}"

  v="$(run_dialog dialog --title "aliases-file" --inputbox "Optional aliases JSON path (--aliases-file)" 10 100 "${ALIASES_FILE}")" || return 1
  ALIASES_FILE="${v}"

  v="$(run_dialog dialog --title "publishers-file" --inputbox "Optional publishers JSON path (--publishers-file)" 10 100 "${PUBLISHERS_FILE}")" || return 1
  PUBLISHERS_FILE="${v}"
}

build_cmd() {
  local -a cmd
  cmd=(python3 "${PY_SCRIPT}" "${TARGET_DIR}")

  case "${MODE}" in
    rebucket) cmd+=(--rebucket) ;;
    audit) cmd+=(--audit) ;;
    promote_unknown) cmd+=(--promote-unknown) ;;
    refine_containers) cmd+=(--refine-containers) ;;
    maintain) cmd+=(--promote-unknown --refine-containers) ;;
    organize) ;;
    *) ;;
  esac

  (( APPLY )) && cmd+=(--apply)
  (( VERBOSE )) && cmd+=(--verbose)
  (( INCLUDE_HIDDEN )) && cmd+=(--include-hidden)
  (( NORMALIZE_EDITIONS )) && cmd+=(--normalize-editions)
  (( NORMALIZE_PUBLISHERS )) && cmd+=(--normalize-publishers)
  (( REFINE_CONTAINERS )) && cmd+=(--refine-containers)
  (( PROMOTE_UNKNOWN )) && cmd+=(--promote-unknown)

  [[ -n "${UNKNOWN_DIR}" ]] && cmd+=(--unknown-dir "${UNKNOWN_DIR}")
  [[ -n "${NO_VERSION_LABEL}" ]] && cmd+=(--no-version-label "${NO_VERSION_LABEL}")
  [[ -n "${ALIASES_FILE}" ]] && cmd+=(--aliases-file "${ALIASES_FILE}")
  [[ -n "${PUBLISHERS_FILE}" ]] && cmd+=(--publishers-file "${PUBLISHERS_FILE}")

  printf "%q " "${cmd[@]}"
}

run_command() {
  local cmdline logfile
  cmdline="$(build_cmd)"
  logfile="$(mktemp "/tmp/organize_apps_tui.XXXXXX.log")"

  if ! dialog --title "Confirm run" --yesno "Run command?\n\n${cmdline}" 18 110; then
    rm -f "${logfile}"
    return 1
  fi

  clear
  echo "Running:"
  echo "${cmdline}"
  echo
  bash -lc "${cmdline}" | tee "${logfile}"
  echo
  read -r -p "Press Enter to view output summary in dialog..."
  dialog --title "Run output" --textbox "${logfile}" 24 110
  rm -f "${logfile}"
}

main_menu() {
  while true; do
    local choice
    choice="$(run_dialog dialog --title "organize_apps TUI" --menu \
      "Target: ${TARGET_DIR}\nMode: ${MODE}\nDry-run is default unless apply is enabled." 20 100 10 \
      target "Select target directory" \
      mode "Choose mode" \
      flags "Toggle boolean options" \
      values "Edit value options" \
      run "Run command now" \
      quit "Exit launcher")" || return 0

    case "${choice}" in
      target) pick_target_dir || true ;;
      mode) pick_mode || true ;;
      flags) configure_flags || true ;;
      values) configure_values || true ;;
      run) run_command || true ;;
      quit) return 0 ;;
      *) ;;
    esac
  done
}

main_menu
