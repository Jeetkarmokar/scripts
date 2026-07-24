#!/bin/bash
# ============================================================
# SubEnumRecon - Subdomain Enumeration & Recon Bash Script
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
    echo "  ____        _     _____                      _             "
    echo " / ___| _   _| |__ | ____|_  ___ __   ___  ___| |_ ___  _ __ "
    echo " \\___ \\| | | | '_ \\|  _| \\ \\/ / '_ \\ / _ \\/ __| __/ _ \\| '__|"
    echo "  ___) | |_| | |_) | |___ >  <| |_) |  __/\\__ \\ || (_) | |   "
    echo " |____/ \\__,_|_.__/|_____/_/\\_\\ .__/ \\___||___/\\__\\___/|_|   "
    echo "                                |_|                            "
    echo -e "${NC}"
    echo -e "${MAGENTA}  [ Bug Bounty Subdomain Enumeration & Recon Script ]${NC}"
    echo -e "${MAGENTA}  [ Version: 1.0 | Author: You ]${NC}"
    echo ""
}

# Help menu
usage() {
    echo -e "${BOLD}Usage:${NC} ./subenumrecon.sh [OPTIONS]"
    echo ""
    echo -e "${BOLD}Options:${NC}"
    echo "  -d, --domain <domain>     Target domain (required)"
    echo "  -o, --output <dir>        Output directory (default: ./recon-<domain>)"
    echo "  -p, --passive             Run passive enumeration only"
    echo "  -a, --active              Run active enumeration (DNS brute force)"
    echo "  -f, --full                Run full recon (passive + active + probing)"
    echo "  -w, --wordlist <file>     Custom wordlist for brute force"
    echo "  -t, --threads <num>       Number of threads (default: 50)"
    echo "  --takeover                Check for subdomain takeover"
    echo "  --screenshots             Take screenshots of live hosts"
    echo "  --nuclei                  Run nuclei vulnerability scan"
    echo "  -h, --help                Show this help menu"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  ./subenumrecon.sh -d example.com -f"
    echo "  ./subenumrecon.sh -d example.com -p --takeover"
    echo "  ./subenumrecon.sh -d example.com -a -w /path/to/wordlist.txt"
    echo ""
}

# Check if required tools are installed
check_tools() {
    local tools=("subfinder" "assetfinder" "amass" "httpx" "waybackurls" "gau" "naabu")
    local missing=()

    echo -e "${YELLOW}[*] Checking required tools...${NC}"
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done

    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}[!] Missing tools: ${missing[*]}${NC}"
        echo -e "${YELLOW}[*] Install them using:${NC}"
        echo "    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        echo "    go install -v github.com/tomnomnom/assetfinder@latest"
        echo "    go install -v github.com/OWASP/Amass/v3/...@master"
        echo "    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        echo "    go install -v github.com/tomnomnom/waybackurls@latest"
        echo "    go install -v github.com/lc/gau/v2/cmd/gau@latest"
        echo "    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        exit 1
    fi

    echo -e "${GREEN}[+] All required tools are installed!${NC}"
}

# Passive Subdomain Enumeration
passive_enum() {
    local domain=$1
    local outdir=$2

    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           PASSIVE SUBDOMAIN ENUMERATION                      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    # 1. Subfinder
    echo -e "${YELLOW}[*] Running subfinder...${NC}"
    subfinder -d "$domain" -silent -o "$outdir/subfinder.txt" 2>/dev/null || true
    local subfinder_count=$(wc -l < "$outdir/subfinder.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[+] Subfinder found: $subfinder_count subdomains${NC}"

    # 2. Assetfinder
    echo -e "${YELLOW}[*] Running assetfinder...${NC}"
    assetfinder --subs-only "$domain" > "$outdir/assetfinder.txt" 2>/dev/null || true
    local assetfinder_count=$(wc -l < "$outdir/assetfinder.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[+] Assetfinder found: $assetfinder_count subdomains${NC}"

    # 3. Amass (passive)
    echo -e "${YELLOW}[*] Running amass (passive)...${NC}"
    timeout 300 amass enum -passive -d "$domain" -o "$outdir/amass.txt" 2>/dev/null || true
    local amass_count=$(wc -l < "$outdir/amass.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[+] Amass found: $amass_count subdomains${NC}"

    # 4. crt.sh (Certificate Transparency)
    echo -e "${YELLOW}[*] Querying crt.sh (Certificate Transparency)...${NC}"
    curl -s "https://crt.sh/?q=%.$domain&output=json" 2>/dev/null | \
        jq -r '.[].name_value' 2>/dev/null | \
        sed 's/\*\.//g' | \
        sort -u > "$outdir/crtsh.txt" || true
    local crtsh_count=$(wc -l < "$outdir/crtsh.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[+] crt.sh found: $crtsh_count subdomains${NC}"

    # 5. RapidDNS
    echo -e "${YELLOW}[*] Querying RapidDNS...${NC}"
    curl -s "https://rapiddns.io/subdomain/$domain?full=1" 2>/dev/null | \
        grep -oP '(?<=<td>)[a-zA-Z0-9\-\.]+\.'"$domain" 2>/dev/null | \
        sort -u > "$outdir/rapiddns.txt" || true
    local rapiddns_count=$(wc -l < "$outdir/rapiddns.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[+] RapidDNS found: $rapiddns_count subdomains${NC}"

    # 6. HackerTarget
    echo -e "${YELLOW}[*] Querying HackerTarget...${NC}"
    curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" 2>/dev/null | \
        cut -d',' -f1 > "$outdir/hackertarget.txt" || true
    local hackertarget_count=$(wc -l < "$outdir/hackertarget.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[+] HackerTarget found: $hackertarget_count subdomains${NC}"

    # Combine all passive results
    echo -e "${YELLOW}[*] Combining and deduplicating passive results...${NC}"
    cat "$outdir/subfinder.txt" "$outdir/assetfinder.txt" "$outdir/amass.txt" \
        "$outdir/crtsh.txt" "$outdir/rapiddns.txt" "$outdir/hackertarget.txt" 2>/dev/null | \
        grep -E "^[a-zA-Z0-9\-\.]+\.$domain$" | \
        sort -u > "$outdir/all_subdomains.txt"

    local total_count=$(wc -l < "$outdir/all_subdomains.txt")
    echo -e "${GREEN}[+] Total unique subdomains found (passive): $total_count${NC}"
}

# Active Subdomain Enumeration (DNS Brute Force)
active_enum() {
    local domain=$1
    local outdir=$2
    local wordlist=$3
    local threads=$4

    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║            ACTIVE SUBDOMAIN ENUMERATION                      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    # Check for puredns or use alternative
    if command -v puredns &> /dev/null; then
        echo -e "${YELLOW}[*] Running puredns brute force...${NC}"
        puredns bruteforce "$wordlist" "$domain" -r /usr/share/wordlists/resolvers.txt \
            -t "$threads" -o "$outdir/puredns.txt" 2>/dev/null || true
    else
        echo -e "${YELLOW}[*] puredns not found, using dnsx for brute force...${NC}"
        if command -v dnsx &> /dev/null; then
            dnsx -d "$domain" -w "$wordlist" -o "$outdir/dnsx_brute.txt" 2>/dev/null || true
        else
            echo -e "${RED}[!] Neither puredns nor dnsx found. Install one for active brute force.${NC}"
            echo "    go install github.com/d3mondev/puredns/v2@latest"
            echo "    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        fi
    fi

    # DNS permutation with gotator (if available)
    if command -v gotator &> /dev/null && [ -f "$outdir/all_subdomains.txt" ]; then
        echo -e "${YELLOW}[*] Running gotator for permutations...${NC}"
        gotator -sub "$outdir/all_subdomains.txt" -perm /usr/share/wordlists/permutations.txt \
            -depth 1 -numbers 10 -mindup -adv -md > "$outdir/permutations.txt" 2>/dev/null || true

        # Resolve permutations
        if command -v puredns &> /dev/null; then
            puredns resolve "$outdir/permutations.txt" -r /usr/share/wordlists/resolvers.txt \
                -o "$outdir/resolved_perms.txt" 2>/dev/null || true
        fi
    fi

    # Combine active results with passive
    echo -e "${YELLOW}[*] Combining active + passive results...${NC}"
    cat "$outdir/all_subdomains.txt" "$outdir/puredns.txt" "$outdir/dnsx_brute.txt" \
        "$outdir/resolved_perms.txt" 2>/dev/null | \
        grep -E "^[a-zA-Z0-9\-\.]+\.$domain$" | \
        sort -u > "$outdir/all_subdomains_final.txt"

    mv "$outdir/all_subdomains_final.txt" "$outdir/all_subdomains.txt"
    local total_count=$(wc -l < "$outdir/all_subdomains.txt")
    echo -e "${GREEN}[+] Total unique subdomains (passive + active): $total_count${NC}"
}

# Live Host Detection
probe_hosts() {
    local outdir=$1

    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              LIVE HOST DETECTION                             ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${YELLOW}[*] Probing for live hosts with httpx...${NC}"
    cat "$outdir/all_subdomains.txt" | httpx -silent -o "$outdir/live_hosts.txt" \
        -title -tech-detect -status-code -json -o "$outdir/live_hosts.json" 2>/dev/null || \
        cat "$outdir/all_subdomains.txt" | httpx -silent -o "$outdir/live_hosts.txt" 2>/dev/null || true

    local live_count=$(wc -l < "$outdir/live_hosts.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[+] Live hosts found: $live_count${NC}"
}

# URL Collection
url_collection() {
    local domain=$1
    local outdir=$2

    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                URL COLLECTION                                ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    # Wayback URLs
    echo -e "${YELLOW}[*] Fetching URLs from Wayback Machine...${NC}"
    cat "$outdir/live_hosts.txt" | waybackurls > "$outdir/wayback_urls.txt" 2>/dev/null || true
    local wb_count=$(wc -l < "$outdir/wayback_urls.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[+] Wayback URLs: $wb_count${NC}"

    # GAU (GetAllUrls)
    echo -e "${YELLOW}[*] Fetching URLs with GAU...${NC}"
    cat "$outdir/all_subdomains.txt" | gau --threads 5 > "$outdir/gau_urls.txt" 2>/dev/null || true
    local gau_count=$(wc -l < "$outdir/gau_urls.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[+] GAU URLs: $gau_count${NC}"

    # Combine URLs
    cat "$outdir/wayback_urls.txt" "$outdir/gau_urls.txt" 2>/dev/null | sort -u > "$outdir/all_urls.txt"
    local total_urls=$(wc -l < "$outdir/all_urls.txt")
    echo -e "${GREEN}[+] Total unique URLs: $total_urls${NC}"
}

# Port Scanning
port_scan() {
    local outdir=$1

    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                 PORT SCANNING                                ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${YELLOW}[*] Running naabu port scan on live hosts...${NC}"
    naabu -list "$outdir/all_subdomains.txt" -o "$outdir/ports.txt" \
        -top-ports 1000 -silent 2>/dev/null || true

    local port_count=$(wc -l < "$outdir/ports.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[+] Open ports found: $port_count${NC}"
}

# Subdomain Takeover Check
takeover_check() {
    local outdir=$1

    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           SUBDOMAIN TAKEOVER CHECK                           ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    if command -v subjack &> /dev/null; then
        echo -e "${YELLOW}[*] Running subjack for takeover detection...${NC}"
        subjack -w "$outdir/all_subdomains.txt" -t 100 -timeout 30 \
            -o "$outdir/takeover.txt" -ssl 2>/dev/null || true
    else
        echo -e "${YELLOW}[*] subjack not found, using nuclei for takeover...${NC}"
        if command -v nuclei &> /dev/null; then
            nuclei -l "$outdir/all_subdomains.txt" -t ~/nuclei-templates/http/takeovers/ \
                -o "$outdir/takeover.txt" 2>/dev/null || true
        fi
    fi

    if [ -f "$outdir/takeover.txt" ] && [ -s "$outdir/takeover.txt" ]; then
        echo -e "${RED}[!] Potential subdomain takeovers found! Check: $outdir/takeover.txt${NC}"
    else
        echo -e "${GREEN}[+] No subdomain takeovers detected.${NC}"
    fi
}

# Screenshot Capture
screenshots() {
    local outdir=$1

    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              SCREENSHOT CAPTURE                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    if command -v aquatone &> /dev/null; then
        echo -e "${YELLOW}[*] Taking screenshots with aquatone...${NC}"
        mkdir -p "$outdir/screenshots"
        cat "$outdir/live_hosts.txt" | aquatone -out "$outdir/screenshots" 2>/dev/null || true
    elif command -v gowitness &> /dev/null; then
        echo -e "${YELLOW}[*] Taking screenshots with gowitness...${NC}"
        mkdir -p "$outdir/screenshots"
        gowitness file -f "$outdir/live_hosts.txt" -P "$outdir/screenshots" 2>/dev/null || true
    else
        echo -e "${YELLOW}[!] No screenshot tool found. Install aquatone or gowitness.${NC}"
        echo "    go install github.com/michenriksen/aquatone@latest"
        echo "    go install github.com/sensepost/gowitness@latest"
    fi
}

# Nuclei Scan
nuclei_scan() {
    local outdir=$1

    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║            NUCLEI VULNERABILITY SCAN                         ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    if command -v nuclei &> /dev/null; then
        echo -e "${YELLOW}[*] Running nuclei scan on live hosts...${NC}"
        nuclei -l "$outdir/live_hosts.txt" -o "$outdir/nuclei_results.txt" \
            -severity critical,high,medium -silent 2>/dev/null || true

        local nuclei_count=$(wc -l < "$outdir/nuclei_results.txt" 2>/dev/null || echo 0)
        echo -e "${GREEN}[+] Nuclei findings: $nuclei_count${NC}"
    else
        echo -e "${YELLOW}[!] nuclei not found. Install with:${NC}"
        echo "    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
    fi
}

# Generate Report
generate_report() {
    local domain=$1
    local outdir=$2

    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              GENERATING REPORT                               ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    local sub_count=$(wc -l < "$outdir/all_subdomains.txt" 2>/dev/null || echo 0)
    local live_count=$(wc -l < "$outdir/live_hosts.txt" 2>/dev/null || echo 0)
    local url_count=$(wc -l < "$outdir/all_urls.txt" 2>/dev/null || echo 0)
    local port_count=$(wc -l < "$outdir/ports.txt" 2>/dev/null || echo 0)

    cat > "$outdir/report.txt" << EOF
============================================================
         SUBDOMAIN ENUMERATION REPORT
         Target: $domain
         Date: $(date)
============================================================

[+] Total Subdomains Found: $sub_count
[+] Live Hosts: $live_count
[+] Total URLs Collected: $url_count
[+] Open Ports Found: $port_count

------------------------------------------------------------
FILES GENERATED:
------------------------------------------------------------
- all_subdomains.txt    : All discovered subdomains
- live_hosts.txt        : Live/responding hosts
- live_hosts.json       : Live hosts with tech details
- all_urls.txt          : Collected URLs
- ports.txt             : Open ports
- wayback_urls.txt      : Wayback Machine URLs
- gau_urls.txt          : GAU URLs

EOF

    if [ -f "$outdir/takeover.txt" ] && [ -s "$outdir/takeover.txt" ]; then
        echo "[!] Subdomain Takeovers: FOUND (see takeover.txt)" >> "$outdir/report.txt"
    else
        echo "[+] Subdomain Takeovers: None detected" >> "$outdir/report.txt"
    fi

    if [ -f "$outdir/nuclei_results.txt" ] && [ -s "$outdir/nuclei_results.txt" ]; then
        echo "[!] Nuclei Findings: FOUND (see nuclei_results.txt)" >> "$outdir/report.txt"
    else
        echo "[+] Nuclei Findings: None detected" >> "$outdir/report.txt"
    fi

    echo "" >> "$outdir/report.txt"
    echo "============================================================" >> "$outdir/report.txt"
    echo "Report generated by SubEnumRecon" >> "$outdir/report.txt"
    echo "============================================================" >> "$outdir/report.txt"

    echo -e "${GREEN}[+] Report saved to: $outdir/report.txt${NC}"
}

# Main function
main() {
    local domain=""
    local output=""
    local passive=false
    local active=false
    local full=false
    local takeover=false
    local screenshots_flag=false
    local nuclei_flag=false
    local wordlist="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    local threads=50

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
            -p|--passive)
                passive=true
                shift
                ;;
            -a|--active)
                active=true
                shift
                ;;
            -f|--full)
                full=true
                shift
                ;;
            -w|--wordlist)
                wordlist="$2"
                shift 2
                ;;
            -t|--threads)
                threads="$2"
                shift 2
                ;;
            --takeover)
                takeover=true
                shift
                ;;
            --screenshots)
                screenshots_flag=true
                shift
                ;;
            --nuclei)
                nuclei_flag=true
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
        output="./recon-$domain"
    fi

    # Create output directory
    mkdir -p "$output"

    banner
    echo -e "${CYAN}[*] Target: $domain${NC}"
    echo -e "${CYAN}[*] Output: $output${NC}"
    echo -e "${CYAN}[*] Started at: $(date)${NC}"
    echo ""

    # Check tools
    check_tools
    echo ""

    # Run enumeration based on mode
    if [ "$full" = true ] || [ "$passive" = true ] || ([ "$passive" = false ] && [ "$active" = false ] && [ "$full" = false ]); then
        passive_enum "$domain" "$output"
        echo ""
    fi

    if [ "$full" = true ] || [ "$active" = true ]; then
        active_enum "$domain" "$output" "$wordlist" "$threads"
        echo ""
    fi

    # Always probe for live hosts if we have subdomains
    if [ -f "$output/all_subdomains.txt" ] && [ -s "$output/all_subdomains.txt" ]; then
        probe_hosts "$output"
        echo ""

        # URL collection
        url_collection "$domain" "$output"
        echo ""

        # Port scanning
        port_scan "$output"
        echo ""
    fi

    # Optional checks
    if [ "$takeover" = true ] || [ "$full" = true ]; then
        takeover_check "$output"
        echo ""
    fi

    if [ "$screenshots_flag" = true ] || [ "$full" = true ]; then
        screenshots "$output"
        echo ""
    fi

    if [ "$nuclei_flag" = true ] || [ "$full" = true ]; then
        nuclei_scan "$output"
        echo ""
    fi

    # Generate report
    generate_report "$domain" "$output"

    echo ""
    echo -e "${GREEN}"
    echo "============================================================"
    echo "  RECON COMPLETE!"
    echo "  Results saved in: $output"
    echo "  Finished at: $(date)"
    echo "============================================================"
    echo -e "${NC}"
}

# Run main
main "$@"
