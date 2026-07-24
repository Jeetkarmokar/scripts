#!/bin/bash
# ============================================================
# crtsh-recon.sh - CRT.sh Subdomain Enumeration Pipeline
# For Bug Bounty Hunters & Pentesters
# ============================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Banner
banner() {
    echo -e "${CYAN}"
    echo "  ____ _____ _   _    _    _   "
    echo " / ___|_   _| | | |  / \\  | |  "
    echo "| |     | | | |_| | / _ \\ | |  "
    echo "| |___  | | |  _  |/ ___ \\| |___"
    echo " \\____| |_| |_| |_/_/   \\_\\____|"
    echo ""
    echo -e "${MAGENTA}  [ CRT.sh Recon Pipeline for Bug Bounty ]${NC}"
    echo -e "${MAGENTA}  [ Version: 1.0 ]${NC}"
    echo ""
}

# Help menu
usage() {
    echo -e "${BOLD}Usage:${NC} ./crtsh-recon.sh [OPTIONS]"
    echo ""
    echo -e "${BOLD}Options:${NC}"
    echo "  -d, --domain <domain>     Target domain (required)"
    echo "  -o, --output <dir>        Output directory (default: ./crtsh-recon-<domain>)"
    echo "  -k, --keep                Keep intermediate files (default: remove them)"
    echo "  -h, --help                Show this help menu"
    echo ""
    echo -e "${BOLD}Pipeline:${NC}"
    echo "  1. Download JSON from crt.sh"
    echo "  2. Extract & filter domains"
    echo "  3. Separate wildcard subdomains"
    echo "  4. Remove '*' from wildcards for subfinder -dL"
    echo "  5. Run subfinder on wildcard domains"
    echo "  6. Merge all results into final crtsh.txt"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  ./crtsh-recon.sh -d example.com"
    echo "  ./crtsh-recon.sh -d example.com -o ./results"
    echo "  ./crtsh-recon.sh -d example.com -k    # keep temp files"
    echo ""
}

# Check if required tools are installed
check_tools() {
    echo -e "${YELLOW}[*] Checking required tools...${NC}"

    local tools=("wget" "jq" "subfinder")
    local missing=()

    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done

    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}[!] Missing tools: ${missing[*]}${NC}"
        echo ""
        echo -e "${YELLOW}[*] Install them using:${NC}"
        echo "    sudo apt install wget jq"
        echo "    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        exit 1
    fi

    echo -e "${GREEN}[+] All required tools are installed!${NC}"
}

# Main recon function
run_recon() {
    local domain="$1"
    local outdir="$2"
    local keep_files="$3"

    mkdir -p "$outdir"
    cd "$outdir"

    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              STEP 1: DOWNLOAD CRT.SH JSON                    ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${YELLOW}[*] Downloading certificate data for: $domain${NC}"
    wget -O "${domain}.json" "https://crt.sh/json?q=${domain}" 2>&1 | grep -E "(saved|HTTP)" || true

    if [ ! -f "${domain}.json" ] || [ ! -s "${domain}.json" ]; then
        echo -e "${RED}[!] Failed to download crt.sh data. Exiting.${NC}"
        exit 1
    fi

    echo -e "${GREEN}[+] JSON downloaded: ${domain}.json${NC}"

    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         STEP 2: EXTRACT & FILTER DOMAINS                     ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${YELLOW}[*] Parsing JSON and extracting domains...${NC}"
    jq -r '.[].name_value' "${domain}.json" | \
        tr '\n' '\n' | \
        sed '/^$/d' | \
        sort -u > domains.txt

    local domain_count=$(wc -l < domains.txt)
    echo -e "${GREEN}[+] Extracted $domain_count unique domains → domains.txt${NC}"

    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         STEP 3: SEPARATE WILDCARD SUBDOMAINS                 ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${YELLOW}[*] Filtering wildcard entries (*.)...${NC}"
    grep "^\\*" domains.txt > wild-cards.txt 2>/dev/null || true

    local wildcard_count=$(wc -l < wild-cards.txt 2>/dev/null || echo 0)
    echo -e "${GREEN}[+] Found $wildcard_count wildcard entries → wild-cards.txt${NC}"

    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║      STEP 4: CLEAN WILDCARDS FOR SUBFINDER INPUT             ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${YELLOW}[*] Removing '*' prefix from wildcards...${NC}"
    sed 's/^\*\.//' wild-cards.txt | \
        sort -u > dL_domains.txt

    local dl_count=$(wc -l < dL_domains.txt)
    echo -e "${GREEN}[+] Cleaned $dl_count domains → dL_domains.txt (ready for subfinder -dL)${NC}"

    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         STEP 5: RUN SUBFINDER ON WILDCARD DOMAINS             ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    if [ "$dl_count" -gt 0 ]; then
        echo -e "${YELLOW}[*] Running subfinder with -dL on cleaned wildcard domains...${NC}"
        subfinder -dL dL_domains.txt -o subfinder-subs.txt 2>/dev/null || true

        local subfinder_count=$(wc -l < subfinder-subs.txt 2>/dev/null || echo 0)
        echo -e "${GREEN}[+] Subfinder found $subfinder_count additional subdomains → subfinder-subs.txt${NC}"
    else
        echo -e "${YELLOW}[!] No wildcard domains to scan with subfinder.${NC}"
        touch subfinder-subs.txt
    fi

    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         STEP 6: MERGE ALL RESULTS INTO FINAL OUTPUT          ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${YELLOW}[*] Combining all discovered subdomains...${NC}"
    cat *.txt | sort -u > crtsh.txt

    local final_count=$(wc -l < crtsh.txt)
    echo -e "${GREEN}[+] Final result: $final_count unique subdomains → crtsh.txt${NC}"

    # Cleanup intermediate files (unless --keep is set)
    if [ "$keep_files" = false ]; then
        echo -e "${YELLOW}[*] Cleaning up intermediate files...${NC}"
        rm -f "${domain}.json" domains.txt wild-cards.txt dL_domains.txt subfinder-subs.txt
        echo -e "${GREEN}[+] Cleanup complete. Only crtsh.txt kept.${NC}"
    else
        echo -e "${YELLOW}[*] Keeping all intermediate files (--keep flag set).${NC}"
    fi

    cd - > /dev/null
}

# Main function
main() {
    local domain=""
    local output=""
    local keep_files=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain)
                domain="$2"
                shift 2
                ;;
            -o|--output)
                output="$2"
                shift 2
                ;;
            -k|--keep)
                keep_files=true
                shift
                ;;
            -h|--help)
                banner
                usage
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Unknown option: $1${NC}"
                usage
                exit 1
                ;;
        esac
    done

    # Validate domain
    if [ -z "$domain" ]; then
        banner
        echo -e "${RED}[!] Error: Domain is required!${NC}"
        usage
        exit 1
    fi

    # Set output directory
    if [ -z "$output" ]; then
        output="./crtsh-recon-${domain}"
    fi

    # Resolve absolute path
    output="$(cd "$(dirname "$output")" && pwd)/$(basename "$output")"

    banner
    echo -e "${CYAN}[*] Target Domain: $domain${NC}"
    echo -e "${CYAN}[*] Output Directory: $output${NC}"
    echo -e "${CYAN}[*] Keep Intermediate Files: $keep_files${NC}"
    echo -e "${CYAN}[*] Started at: $(date)${NC}"
    echo ""

    # Check tools
    check_tools
    echo ""

    # Run the pipeline
    run_recon "$domain" "$output" "$keep_files"

    echo ""
    echo -e "${GREEN}"
    echo "============================================================"
    echo "  CRT.SH RECON COMPLETE!"
    echo "  Final results: ${output}/crtsh.txt"
    echo "  Finished at: $(date)"
    echo "============================================================"
    echo -e "${NC}"
}

# Run main
main "$@"
