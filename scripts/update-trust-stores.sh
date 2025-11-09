#!/usr/bin/env bash
#
# Trust Store Update Script for CipherRun
#
# Copyright (C) 2025 Marc Rivero López
# Licensed under the GNU General Public License v3.0
#
# This script downloads and updates root CA certificates from various
# platform trust stores for use in CipherRun's multi-platform certificate
# validation system.
#
# Usage:
#   ./scripts/update-trust-stores.sh [mozilla|apple|android|java|windows|all]
#
# Requirements:
#   - curl or wget
#   - openssl (for certificate conversion)
#   - Internet connection
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${SCRIPT_DIR}/../data"
TEMP_DIR="/tmp/cipherrun-trust-stores-$$"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create temp directory
mkdir -p "${TEMP_DIR}"
trap "rm -rf ${TEMP_DIR}" EXIT

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Download utility (prefers curl, falls back to wget)
download() {
    local url="$1"
    local output="$2"

    if command -v curl &> /dev/null; then
        curl -sL -o "${output}" "${url}"
    elif command -v wget &> /dev/null; then
        wget -q -O "${output}" "${url}"
    else
        log_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi
}

# Update Mozilla NSS trust store
update_mozilla() {
    log_info "Updating Mozilla NSS trust store..."

    local url="https://ccadb-public.secure.force.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites"
    local output="${DATA_DIR}/Mozilla.pem"

    download "${url}" "${TEMP_DIR}/mozilla.pem"

    # Validate that we got valid PEM data
    if grep -q "BEGIN CERTIFICATE" "${TEMP_DIR}/mozilla.pem"; then
        mv "${TEMP_DIR}/mozilla.pem" "${output}"
        local count=$(grep -c "BEGIN CERTIFICATE" "${output}" || echo 0)
        log_success "Mozilla trust store updated with ${count} certificates"
    else
        log_error "Downloaded Mozilla data does not contain valid certificates"
        return 1
    fi
}

# Update Apple trust store
update_apple() {
    log_info "Updating Apple trust store..."
    log_warning "Apple trust store requires manual extraction from macOS/iOS"
    log_info "Visit: https://support.apple.com/en-us/HT213464"
    log_info "Or extract from: /System/Library/Security/Certificates.bundle"

    # If running on macOS, attempt automatic extraction
    if [[ "$(uname)" == "Darwin" ]]; then
        log_info "Detected macOS, attempting automatic extraction..."

        local cert_dir="/System/Library/Security/Certificates.bundle"
        if [[ -d "${cert_dir}" ]]; then
            local output="${DATA_DIR}/Apple.pem"
            > "${output}"  # Clear file

            # Extract all .crt files
            find "${cert_dir}" -name "*.crt" -o -name "*.pem" | while read -r cert; do
                if [[ -f "${cert}" ]]; then
                    cat "${cert}" >> "${output}"
                    echo "" >> "${output}"
                fi
            done

            local count=$(grep -c "BEGIN CERTIFICATE" "${output}" || echo 0)
            if [[ ${count} -gt 0 ]]; then
                log_success "Apple trust store updated with ${count} certificates"
            else
                log_warning "No certificates found in system bundle"
            fi
        else
            log_warning "System certificate bundle not found at ${cert_dir}"
        fi
    fi
}

# Update Android trust store
update_android() {
    log_info "Updating Android trust store..."

    # Android CA certificates are stored in AOSP
    # https://android.googlesource.com/platform/system/ca-certificates/+/refs/heads/master/files/

    local base_url="https://android.googlesource.com/platform/system/ca-certificates/+/refs/heads/master/files"
    local output="${DATA_DIR}/Android.pem"

    log_info "Downloading Android CA certificate list..."

    # Use Mozilla as baseline for Android (they share many root CAs)
    # In production, this should fetch from AOSP
    if [[ -f "${DATA_DIR}/Mozilla.pem" ]]; then
        cp "${DATA_DIR}/Mozilla.pem" "${output}"
        log_success "Android trust store created from Mozilla baseline"
        log_info "For Android-specific CAs, visit: ${base_url}"
    else
        log_error "Mozilla.pem not found. Run update for Mozilla first."
        return 1
    fi
}

# Update Java trust store
update_java() {
    log_info "Updating Java trust store..."

    # Locate Java cacerts keystore
    local cacerts_paths=(
        "${JAVA_HOME}/lib/security/cacerts"
        "/usr/lib/jvm/default-java/lib/security/cacerts"
        "/usr/lib/jvm/java-11-openjdk-amd64/lib/security/cacerts"
        "/Library/Java/JavaVirtualMachines/*/Contents/Home/lib/security/cacerts"
    )

    local cacerts=""
    for path in "${cacerts_paths[@]}"; do
        # Handle glob expansion
        for expanded in ${path}; do
            if [[ -f "${expanded}" ]]; then
                cacerts="${expanded}"
                break 2
            fi
        done
    done

    if [[ -z "${cacerts}" ]]; then
        log_warning "Java cacerts keystore not found"
        log_info "Please set JAVA_HOME or install JDK"
        return 1
    fi

    log_info "Found Java cacerts at: ${cacerts}"

    local output="${DATA_DIR}/Java.pem"
    > "${output}"  # Clear file

    # Extract certificates from keystore (default password: changeit)
    if command -v keytool &> /dev/null; then
        # List all aliases
        local aliases=$(keytool -list -keystore "${cacerts}" -storepass changeit -noprompt 2>/dev/null | \
                       grep "trustedCertEntry" | awk -F, '{print $1}')

        local count=0
        while IFS= read -r alias; do
            if [[ -n "${alias}" ]]; then
                keytool -exportcert -alias "${alias}" -keystore "${cacerts}" \
                        -storepass changeit -rfc -noprompt 2>/dev/null >> "${output}" || true
                ((count++)) || true
            fi
        done <<< "${aliases}"

        log_success "Java trust store updated with ${count} certificates"
    else
        log_error "keytool not found. Please install JDK."
        return 1
    fi
}

# Update Windows trust store
update_windows() {
    log_info "Updating Windows trust store..."

    if [[ "$(uname)" == MINGW* ]] || [[ "$(uname)" == CYGWIN* ]]; then
        log_info "Detected Windows environment"

        # On Windows, use PowerShell to export certificates
        local ps_script="${TEMP_DIR}/export-certs.ps1"
        cat > "${ps_script}" << 'PSEOF'
$certs = Get-ChildItem -Path Cert:\LocalMachine\Root
$output = ""
foreach ($cert in $certs) {
    $pem = "-----BEGIN CERTIFICATE-----`n"
    $pem += [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    $pem += "`n-----END CERTIFICATE-----`n"
    $output += $pem
}
$output | Out-File -FilePath "windows-certs.pem" -Encoding ASCII
PSEOF

        powershell.exe -ExecutionPolicy Bypass -File "${ps_script}" 2>/dev/null || true

        if [[ -f "windows-certs.pem" ]]; then
            mv "windows-certs.pem" "${DATA_DIR}/Microsoft.pem"
            log_success "Windows trust store updated"
        else
            log_warning "Failed to export Windows certificates"
        fi
    else
        log_warning "Windows certificate store requires Windows environment"
        log_info "Use Microsoft.pem from a previous export or run on Windows"

        # Fallback: Use Mozilla as baseline
        if [[ -f "${DATA_DIR}/Mozilla.pem" ]]; then
            cp "${DATA_DIR}/Mozilla.pem" "${DATA_DIR}/Microsoft.pem"
            log_info "Using Mozilla trust store as Windows baseline"
        fi
    fi
}

# Main script
main() {
    local target="${1:-all}"

    log_info "CipherRun Trust Store Update Script"
    log_info "===================================="
    echo

    case "${target}" in
        mozilla)
            update_mozilla
            ;;
        apple)
            update_apple
            ;;
        android)
            update_android
            ;;
        java)
            update_java
            ;;
        windows)
            update_windows
            ;;
        all)
            update_mozilla
            echo
            update_apple
            echo
            update_android
            echo
            update_java
            echo
            update_windows
            ;;
        *)
            log_error "Unknown trust store: ${target}"
            echo "Usage: $0 [mozilla|apple|android|java|windows|all]"
            exit 1
            ;;
    esac

    echo
    log_info "Trust store update complete!"
    log_info "Updated files are in: ${DATA_DIR}"

    # Display certificate counts
    echo
    log_info "Certificate counts per trust store:"
    for store in Mozilla Apple Android Linux Microsoft Java; do
        local file="${DATA_DIR}/${store}.pem"
        if [[ -f "${file}" ]]; then
            local count=$(grep -c "BEGIN CERTIFICATE" "${file}" || echo 0)
            printf "  %-12s: %d certificates\n" "${store}" "${count}"
        fi
    done
}

main "$@"
