#!/bin/bash

# Copyright 2025 ellipse2v
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# AssetScriber - An SBOM generation and discovery script
# It uses syft to scan local and remote targets without installing agents.
# Version 2: Deploys itself on remote machines instead of rsyncing everything

set -o pipefail

# --- Configuration ---
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
BIN_DIR="${SCRIPT_DIR}/bin"
SYFT_PATH="${BIN_DIR}/syft"
JQ_LOCAL_PATH="${BIN_DIR}/jq"
OUTPUT_DIR="${SCRIPT_DIR}/asset_scriber_output"
INTERMEDIATE_DIR="${OUTPUT_DIR}/intermediate"
CSV_OUTPUT_PATH="${OUTPUT_DIR}/master_asset_list.csv"
STATUS_REPORT_LOG="${OUTPUT_DIR}/status_report.log"
SYFT_INSTALL_SCRIPT_URL="https://raw.githubusercontent.com/anchore/syft/main/install.sh"

# Remote deployment configuration
REMOTE_WORK_DIR="/tmp/assetscriber_$$"
REMOTE_SYFT_PATH="${REMOTE_WORK_DIR}/syft"

# --- Global Variables ---
IS_ROOT=0
JQ_PATH="" # Will be set to the path of the jq executable
declare -a SCANNED_HOSTS

# --- Utility Functions ---

# Logs a message to the status report and stdout
log_msg() {
    local type=$1
    local msg=$2
    local color_red='\033[0;31m'
    local color_green='\033[0;32m'
    local color_yellow='\033[0;33m'
    local color_blue='\033[0;34m'
    local color_reset='\033[0m'
    local formatted_msg

    case "$type" in
        "INFO") formatted_msg="${color_blue}[INFO]${color_reset} $msg" ;;
        "SUCCESS") formatted_msg="${color_green}[SUCCESS]${color_reset} $msg" ;;
        "WARN") formatted_msg="${color_yellow}[WARN]${color_reset} $msg" ;;
        "ERROR") formatted_msg="${color_red}[ERROR]${color_reset} $msg" ;;
        *) formatted_msg="$msg" ;;
    esac

    echo -e "$formatted_msg"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$type] $msg" >> "$STATUS_REPORT_LOG"
}

# Checks if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Checks if the script is running as root
check_root_privileges() {
    if [[ $EUID -eq 0 ]]; then
        IS_ROOT=1
        log_msg "INFO" "Script is running with root privileges."
    else
        IS_ROOT=0
        log_msg "WARN" "Script is running without root privileges. Scans will be limited."
    fi
}

# Displays the help message
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -p, --path <path>        Scan a local filesystem path."
    echo "  -c, --config <file>      Scan hosts listed in the specified config file."
    echo "                           Format per line: <ip/host> [user] [password]"
    echo "  -d, --discover           Discover and attempt to scan hosts on the local network."
    echo "      --os-only            Only include operating system packages in the output."
    echo "  -h, --help               Display this help message."
    echo
    echo "If no option is provided, the script scans the local system ('/' if root, '.' otherwise)."
}

# --- Core Functions ---

# Sets up syft: checks for its existence, otherwise downloads it.
setup_syft() {
    log_msg "INFO" "Checking for syft executable..."
    if [[ -x "$SYFT_PATH" ]]; then
        log_msg "SUCCESS" "syft found at '$SYFT_PATH'."
        return 0
    fi

    log_msg "WARN" "syft not found. Attempting to download..."
    if ! command_exists "curl"; then
        log_msg "ERROR" "Cannot download syft because 'curl' is not installed. Please install curl or place the syft binary at '$SYFT_PATH'."
        return 1
    fi

    mkdir -p "$BIN_DIR"
    if curl -sSfL "$SYFT_INSTALL_SCRIPT_URL" | sh -s -- -b "$BIN_DIR"; then
        if [[ -x "$SYFT_PATH" ]]; then
            log_msg "SUCCESS" "syft was successfully installed to '$SYFT_PATH'."
            return 0
        fi
    fi

    log_msg "ERROR" "Failed to install syft."
    rm -rf "$SYFT_PATH"
    return 1
}

# Sets up jq: checks for system, local, or downloads it.
setup_jq() {
    log_msg "INFO" "Checking for jq executable..."
    if command_exists "jq"; then
        JQ_PATH=$(command -v "jq")
        log_msg "SUCCESS" "Found system-wide jq at '$JQ_PATH'."
        return 0
    fi

    if [[ -x "$JQ_LOCAL_PATH" ]]; then
        JQ_PATH="$JQ_LOCAL_PATH"
        log_msg "SUCCESS" "Found local jq at '$JQ_PATH'."
        return 0
    fi

    log_msg "WARN" "jq not found. Attempting to download a static binary..."
    if ! command_exists "curl"; then
        log_msg "ERROR" "Cannot download jq because 'curl' is not installed. This is a critical dependency."
        return 1
    fi

    local arch
    arch=$(uname -m)
    local jq_url
    local jq_version="1.7.1" # Using a specific stable version

    case "$arch" in
        "x86_64")
            jq_url="https://github.com/jqlang/jq/releases/download/jq-${jq_version}/jq-linux-amd64"
            ;;
        "aarch64")
            jq_url="https://github.com/jqlang/jq/releases/download/jq-${jq_version}/jq-linux-arm64"
            ;;
        *)
            log_msg "ERROR" "Unsupported architecture '$arch' for automatic jq download. Please install jq manually."
            return 1
            ;;
    esac

    log_msg "INFO" "Downloading jq for '$arch' from '$jq_url'..."
    mkdir -p "$BIN_DIR"
    if curl -sSL -o "$JQ_LOCAL_PATH" "$jq_url"; then
        chmod +x "$JQ_LOCAL_PATH"
        if [[ -x "$JQ_LOCAL_PATH" ]]; then
            JQ_PATH="$JQ_LOCAL_PATH"
            log_msg "SUCCESS" "jq was successfully downloaded to '$JQ_PATH'."
            return 0
        fi
    fi

    log_msg "ERROR" "Failed to download or make jq executable."
    rm -f "$JQ_LOCAL_PATH"
    return 1
}


# Processes a JSON SBOM file and creates an intermediate CSV file.
# $1: path to the sbom.json file
# $2: hostname of the scanned machine
process_sbom_to_csv() {
    local sbom_file=$1
    local hostname=$2
    local intermediate_csv_path="${INTERMEDIATE_DIR}/${hostname}.csv"

    if [[ -z "$JQ_PATH" ]]; then
        log_msg "ERROR" "jq path is not set. Cannot process SBOM JSON files."
        return 1
    fi

    log_msg "INFO" "Creating intermediate data for host '$hostname'..."

    local distro_id
    distro_id=$("$JQ_PATH" -r '.metadata.component.properties[]? | select(.name == "distro:id") | .value' "$sbom_file")
    [[ -z "$distro_id" ]] && distro_id="unknown"

    # This filter creates a unique package identifier and stores it.
    # The output is a simple two-column CSV: package_identifier,hostname
    local jq_filter
    jq_filter=$(cat <<'EOF'
.components[]? |
(
    . as $component |
    (if $component.type == "go-module" and ($component.name | contains("/")) then
        ($component.name | split("/") | .[-1])
    else
        $component.name
    end) as $final_name |
    [
        $distro,
        $final_name,
        $component.version,
        ($component.cpe // "N/A"),
        ($component.purl // "N/A")
    ] | @csv
)
EOF
)

    # Create the header for the intermediate file
    echo "distro,name,version,cpe,purl" > "$intermediate_csv_path"
    "$JQ_PATH" -r --arg distro "$distro_id" "$jq_filter" "$sbom_file" >> "$intermediate_csv_path"

    log_msg "SUCCESS" "Intermediate data for '$hostname' created at '$intermediate_csv_path'."
}

# Performs a local scan on a given directory path.
# $1: path to scan
# $2: hostname for output files
# $3: os_only flag ("true" or "false")
perform_local_scan() {
    local scan_path=$1
    local hostname=$2
    local os_only=$3
    local sbom_output_path="${OUTPUT_DIR}/sbom_${hostname//\//_}.json"

    log_msg "INFO" "Starting local scan for host: '$hostname' (Path: $scan_path)"

    local syft_args=("scan" "dir:$scan_path" "--output" "cyclonedx-json=$sbom_output_path")

    if [[ "$os_only" == "true" ]]; then
        syft_args+=("--scope" "squashed")
    fi

    "$SYFT_PATH" "${syft_args[@]}"
    
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_msg "ERROR" "Syft scan failed for '$hostname' with exit code $exit_code."
        rm -f "$sbom_output_path"
        return 1
    fi

    log_msg "SUCCESS" "SBOM generated for '$hostname' at '$sbom_output_path'."
    process_sbom_to_csv "$sbom_output_path" "$hostname"
}

# Constructs an SSH command with appropriate options
# $1: user
# $2: host
# $3: password (optional)
# Returns: ssh command array in SSH_CMD variable
build_ssh_command() {
    local user=$1
    local host=$2
    local pass=$3
    
    local ssh_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
    
    if [[ -n "$pass" ]]; then
        if ! command_exists "sshpass"; then
            log_msg "ERROR" "sshpass is required for password authentication but not found."
            return 1
        fi
        SSH_CMD=("sshpass" "-p" "$pass" "ssh" $ssh_opts "$user@$host")
    else
        SSH_CMD=("ssh" $ssh_opts "$user@$host")
    fi
    return 0
}

# Constructs an SCP command with appropriate options
# $1: user
# $2: host
# $3: password (optional)
# Returns: scp command array in SCP_CMD variable
build_scp_command() {
    local user=$1
    local host=$2
    local pass=$3
    
    local ssh_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
    
    if [[ -n "$pass" ]]; then
        if ! command_exists "sshpass"; then
            log_msg "ERROR" "sshpass is required for password authentication but not found."
            return 1
        fi
        SCP_CMD=("sshpass" "-p" "$pass" "scp" $ssh_opts)
    else
        SCP_CMD=("scp" $ssh_opts)
    fi
    return 0
}

# Performs a remote scan by deploying syft on the remote host
# $1: hostname
# $2: user
# $3: password (optional)
# $4: path to scan on remote host
# $5: os_only flag ("true" or "false")
perform_remote_scan() {
    local host=$1
    local user=$2
    local pass=$3
    local scan_target=$4
    local os_only=$5

    log_msg "INFO" "Starting remote scan for '$user@$host' (Path: $scan_target)"

    # Build SSH and SCP commands
    local SSH_CMD
    local SCP_CMD
    build_ssh_command "$user" "$host" "$pass" || return 1
    build_scp_command "$user" "$host" "$pass" || return 1

    # Test SSH connectivity
    log_msg "INFO" "Testing SSH connection to '$user@$host'..."
    if ! "${SSH_CMD[@]}" "echo 'SSH connection successful'" &>/dev/null; then
        log_msg "ERROR" "SSH connection to '$user@$host' failed."
        return 1
    fi
    log_msg "SUCCESS" "SSH connection to '$user@$host' established."

    # Create remote work directory
    log_msg "INFO" "Creating remote work directory '$REMOTE_WORK_DIR' on '$host'..."
    if ! "${SSH_CMD[@]}" "mkdir -p '$REMOTE_WORK_DIR'"; then
        log_msg "ERROR" "Failed to create remote work directory on '$host'."
        return 1
    fi

    # Deploy syft to remote host
    log_msg "INFO" "Deploying syft to '$host'..."
    if [[ ! -f "$SYFT_PATH" ]]; then
        log_msg "ERROR" "Local syft binary not found at '$SYFT_PATH'."
        return 1
    fi

    if ! "${SCP_CMD[@]}" "$SYFT_PATH" "$user@$host:$REMOTE_SYFT_PATH"; then
        log_msg "ERROR" "Failed to copy syft to '$host'."
        "${SSH_CMD[@]}" "rm -rf '$REMOTE_WORK_DIR'" 2>/dev/null
        return 1
    fi

    # Make syft executable on remote host
    log_msg "INFO" "Making syft executable on '$host'..."
    if ! "${SSH_CMD[@]}" "chmod +x '$REMOTE_SYFT_PATH'"; then
        log_msg "ERROR" "Failed to make syft executable on '$host'."
        "${SSH_CMD[@]}" "rm -rf '$REMOTE_WORK_DIR'" 2>/dev/null
        return 1
    fi

    # Execute syft scan on remote host
    log_msg "INFO" "Executing syft scan on '$host' (this may take some time)..."
    local remote_sbom_path="${REMOTE_WORK_DIR}/sbom_${host}.json"
    local syft_cmd="'$REMOTE_SYFT_PATH' scan 'dir:$scan_target' --output 'cyclonedx-json=$remote_sbom_path'"
    
    if [[ "$os_only" == "true" ]]; then
        syft_cmd="$syft_cmd --scope squashed"
    fi

    if ! "${SSH_CMD[@]}" "$syft_cmd"; then
        log_msg "ERROR" "Syft scan failed on '$host'."
        "${SSH_CMD[@]}" "rm -rf '$REMOTE_WORK_DIR'" 2>/dev/null
        return 1
    fi
    log_msg "SUCCESS" "Syft scan completed on '$host'."

    # Retrieve the SBOM file
    log_msg "INFO" "Retrieving SBOM file from '$host'..."
    local local_sbom_path="${OUTPUT_DIR}/sbom_${host}.json"
    if ! "${SCP_CMD[@]}" "$user@$host:$remote_sbom_path" "$local_sbom_path"; then
        log_msg "ERROR" "Failed to retrieve SBOM file from '$host'."
        "${SSH_CMD[@]}" "rm -rf '$REMOTE_WORK_DIR'" 2>/dev/null
        return 1
    fi
    log_msg "SUCCESS" "SBOM file retrieved from '$host'."

    # Clean up remote deployment
    log_msg "INFO" "Cleaning up remote deployment on '$host'..."
    if "${SSH_CMD[@]}" "rm -rf '$REMOTE_WORK_DIR'"; then
        log_msg "SUCCESS" "Remote deployment cleaned up on '$host'."
    else
        log_msg "WARN" "Failed to clean up remote deployment on '$host'. Manual cleanup may be required."
    fi

    # Process the retrieved SBOM
    process_sbom_to_csv "$local_sbom_path" "$host"
    local scan_exit_code=$?

    if [[ $scan_exit_code -eq 0 ]]; then
        SCANNED_HOSTS+=("$host")
    fi
}

# Generates the final, pivoted CSV from all intermediate files.
generate_final_csv() {
    log_msg "INFO" "Generating the final master CSV file..."

    local intermediate_files=("$INTERMEDIATE_DIR"/*.csv)
    if [[ ! -e "${intermediate_files[0]}" ]]; then
        log_msg "WARN" "No intermediate CSV files were found. Skipping final CSV generation."
        return
    fi

    local hosts=()
    for f in "${intermediate_files[@]}"; do
        hosts+=("$(basename "$f" .csv)")
    done
    local host_list
    host_list=$(printf ",%s" "${hosts[@]}")
    
    # Create the header
    echo "distro,name,version,cpe,purl${host_list}" > "$CSV_OUTPUT_PATH"

    # Awk script to perform the pivot
    local awk_script
    awk_script=$(cat <<'EOF'
BEGIN { FS=","; OFS="," }
{
    # Build a unique key for the package
    package_key = "";
    for (i = 1; i <= 5; i++) {
        package_key = package_key $i (i < 5 ? OFS : "");
    }
    
    # Get the hostname from the filename
    hostname = FILENAME
    sub(/.+\//, "", hostname)
    sub(/\.csv$/, "", hostname)

    # Store which hosts have which package
    packages[package_key, hostname] = 1
    
    # Keep a list of unique package keys
    if (! (package_key in unique_packages)) {
        unique_packages[package_key] = 1
    }
}
END {
    # Get the list of hosts from the ARGV
    # The last element is the script itself, so we ignore it
    for (i = 1; i < ARGC; i++) {
        hostname = ARGV[i]
        sub(/.+\//, "", hostname)
        sub(/\.csv$/, "", hostname)
        host_order[i] = hostname
    }
    
    # Iterate through unique packages and print the row
    for (pkg in unique_packages) {
        printf "%s", pkg
        for (i = 1; i < ARGC; i++) {
            hostname = host_order[i]
            if (packages[pkg, hostname] == 1) {
                printf ",1"
            } else {
                printf ",0"
            }
        }
        printf "\n"
    }
}
EOF
)

    # We use tail -n +2 to skip the header of each intermediate file
    gawk "$awk_script" "${intermediate_files[@]}" >> "$CSV_OUTPUT_PATH"

    log_msg "SUCCESS" "Master CSV file created at '$CSV_OUTPUT_PATH'."
}

# Discovers hosts on the network and attempts to scan them.
# $1: os_only flag ("true" or "false")
discover_network() {
    local os_only=$1
    if ! command_exists "nmap"; then
        log_msg "ERROR" "Skipping network discovery: 'nmap' command not found."
        return 1
    fi
    if ! command_exists "ip"; then
        log_msg "ERROR" "Skipping network discovery: 'ip' command (from iproute2) not found."
        return 1
    fi

    log_msg "INFO" "Discovering hosts on the local network..."
    local subnet
    subnet=$(ip -o -f inet addr show | awk '/scope global/ {print $4}' | head -n 1)
    if [[ -z "$subnet" ]]; then
        log_msg "ERROR" "Could not determine local subnet."
        return 1
    fi

    log_msg "INFO" "Scanning subnet '$subnet' with nmap..."
    local hosts
    hosts=$(nmap -sn "$subnet" | awk '/Nmap scan report for/{print $5}')
    
    log_msg "INFO" "Discovered hosts: $hosts"

    local current_user
    current_user=$(whoami)
    for host in $hosts; do
        log_msg "INFO" "Attempting to scan discovered host '$host' as user '$current_user'."
        log_msg "WARN" "This will only work if passwordless SSH key authentication is configured for '$current_user@$host'."
        # Discovery mode ignores -p and does a full system scan with the specified os_only filter.
        perform_remote_scan "$host" "$current_user" "" "/" "$os_only"
    done
}

# --- Main Entry Point ---

main() {
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$INTERMEDIATE_DIR"
    echo "AssetScriber Status Report - $(date)" > "$STATUS_REPORT_LOG"
    echo "-------------------------------------" >> "$STATUS_REPORT_LOG"

    if ! setup_syft || ! setup_jq; then
        log_msg "ERROR" "Critical dependency setup failed. Exiting."
        exit 1
    fi

    # --- Argument Parsing ---
    local scan_path_arg=""
    local config_file_arg=""
    local discover_arg=0
    local os_only_arg="false"

    # A simple `while` loop is used for broad compatibility.
    while [[ $# -gt 0 ]]; do
        key="$1"
        case $key in
            -h|--help) show_help; exit 0 ;;
            -p|--path) scan_path_arg="$2"; shift 2 ;;
            -c|--config) config_file_arg="$2"; shift 2 ;;
            -d|--discover) discover_arg=1; shift ;;
            --os-only) os_only_arg="true"; shift ;;
            *) log_msg "ERROR" "Unknown option: $1"; show_help; exit 1 ;;
        esac
    done

    # --- Mode Selection Logic ---
    local scan_target
    local final_os_only

    if [[ -n "$scan_path_arg" ]]; then
        # Mode 1: Path Scan. --os-only acts as a filter.
        log_msg "INFO" "Mode selected: Path Scan on '$scan_path_arg'"
        scan_target="$scan_path_arg"
        final_os_only="$os_only_arg"
    elif [[ "$os_only_arg" == "true" ]]; then
        # Mode 2: OS-Only Scan. No -p path was given.
        log_msg "INFO" "Mode selected: OS-Only Scan"
        scan_target="/"
        final_os_only="true"
    else
        # Mode 3: Full System Scan (Default).
        log_msg "INFO" "Mode selected: Full System Scan"
        scan_target="/"
        final_os_only="false"
    fi

    # --- Execution ---
    check_root_privileges

    if [[ -n "$config_file_arg" ]]; then
        # Scan remote hosts from config file
        if [[ ! -f "$config_file_arg" ]]; then
            log_msg "ERROR" "Configuration file '$config_file_arg' not found."
        else
            while IFS= read -r line || [[ -n "$line" ]]; do
                [[ -z "$line" || "$line" =~ ^#.* ]] && continue
                read -r -a parts <<< "$line"
                local host=${parts[0]}
                local user=${parts[1]:-$(whoami)}
                local pass=${parts[2]}
                perform_remote_scan "$host" "$user" "$pass" "$scan_target" "$final_os_only"
            done < "$config_file_arg"
        fi
    fi

    if [[ "$discover_arg" -eq 1 ]]; then
        # Discover and scan hosts on the network
        # Note: Discovery mode uses the selected os-only filter but always does a full system scan.
        log_msg "INFO" "Starting network discovery..."
        discover_network "$final_os_only"
    fi

    if [[ -z "$config_file_arg" && "$discover_arg" -eq 0 ]]; then
        # No remote options given, perform a local scan
        perform_local_scan "$scan_target" "localhost" "$final_os_only"
    fi

    generate_final_csv

    log_msg "SUCCESS" "Operation finished. Results are in the '$OUTPUT_DIR' directory."
}

main "$@"