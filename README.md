# AssetScriber

AssetScriber is a shell script designed to generate Software Bill of Materials (SBOMs) for local and remote Linux systems. It uses Anchore's `syft` to perform the scans and is built to be as non-intrusive as possible, with a strong emphasis on running without installing any software on remote targets.

## Features

- **Multiple Scan Modes**: Choose between scanning a specific path, scanning for OS packages only, or performing a full system scan.
- **Zero Remote Installation**: To scan a remote machine, the script transfers the target filesystem to the local machine using `rsync` and scans it locally. **No agent or software is installed on the remote host.**
- **Automatic Dependency Management**: Downloads `syft` and `jq` to a local `./bin` directory if they are not found on the system. It can also use pre-downloaded binaries for offline use.
- **Consolidated Output**: Generates a detailed CycloneDX JSON SBOM for each target and a master CSV file consolidating all discovered packages.
- **Network Discovery**: Can use `nmap` to discover other hosts on the local network and attempt to scan them.
- **Robust Status Reporting**: Logs all actions, warnings, and skips to a `status_report.log` file, providing a clear audit trail.

## Prerequisites

The script attempts to be self-sufficient but relies on a few common tools. It will log an error and skip the relevant task if a tool is not found.

- **`curl`**: (Optional) Required for the automatic download of `syft` and `jq`.
- **`rsync`**: **(Required for remote scans)**.
- **`ssh`**: **(Required for remote scans)**.
- **`nmap`**: (Optional) Required only for the network discovery feature (`-d`).
- **`sshpass`**: (Optional) Required only for password-based authentication to remote hosts.

## Usage

The script operates in one of three modes, determined by the flags you provide. These modes are mutually exclusive in what they target.

### Mode 1: Path Scan
Scans a specific directory.
- **Trigger**: `-p, --path <path>`
- **Example**: `./asset-scriber.sh -p /var/www`
- **Details**: Scans only the `/var/www` directory. You can add `--os-only` to filter the results for OS packages found within that path.

### Mode 2: OS-Only Scan
Scans the entire system but only reports packages installed by the OS package manager (e.g., rpm, deb).
- **Trigger**: `--os-only` (used *without* the `-p` flag)
- **Example**: `sudo ./asset-scriber.sh --os-only`
- **Details**: This is useful for getting a quick inventory of just the base system packages.

### Mode 3: Full System Scan (Default)
Scans the entire filesystem for all types of packages (OS, Python, Node.js, etc.).
- **Trigger**: No flags, or only `-c` or `-d`.
- **Example**: `sudo ./asset-scriber.sh`
- **Details**: This is the most comprehensive scan mode.

---

### Applying Modes to Remote Hosts

The selected mode applies to all remote hosts specified with the `-c` flag.

- `sudo ./asset-scriber.sh -c hosts.conf -p /etc` will scan `/etc` on all remote hosts.
- `sudo ./asset-scriber.sh -c hosts.conf --os-only` will perform an OS-only scan on all remote hosts.
- `sudo ./asset-scriber.sh -c hosts.conf` will perform a full system scan on all remote hosts.

### Other Options

- **`-c, --config <file>`**: Specifies a configuration file of remote hosts to scan.
- **`-d, --discover`**: Discovers hosts on the local network. The scan mode (`--os-only` or Full) will be applied to them. The `-p` flag is ignored in discovery mode.
- **`-h, --help`**: Displays the help message.

## Important Considerations

- **Disk Space**: Remote scanning can consume a **significant amount of local disk space** because it temporarily copies the remote filesystem.
- **Permissions**: For full system scans or OS-only scans, the script should be run with `sudo`. For remote scans, the SSH user needs `sudo` or root access to read all files.
- **Offline Mode**: To run without internet, place pre-downloaded `syft` and `jq` binaries in a `./bin` directory next to the script.

## Output

All output is placed in the `asset_scriber_output/` directory:
- **`status_report.log`**: A detailed log of all operations.
- **`sbom_<hostname>.json`**: A CycloneDX JSON SBOM for each scanned host.
- **`master_asset_list.csv`**: The final, consolidated CSV report with the header `hostname,distro,name,version,package`.
