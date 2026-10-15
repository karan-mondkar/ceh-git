
#!/usr/bin/env bash
set -uo pipefail

# Usage:
# ./pcap_analyzer.sh capture.pcap
# ./pcap_analyzer.sh ~/captures ~/reports

INPUT="${1:-}"
OUTDIR="${2:-./packet_reports}"

if [[ -z "$INPUT" || ! -e "$INPUT" ]]; then
    echo "Usage: $0 <capture-file-or-directory> [output-directory]"
    exit 1
fi

if ! command -v tshark >/dev/null 2>&1; then
    echo "[ERROR] Install TShark: sudo apt install tshark"
    exit 1
fi

mkdir -p "$OUTDIR"
OUTDIR="$(realpath "$OUTDIR")"

convert_capture() {
    local FILE="$1"
    local BASE
    local DIR
    local PREFIX

    BASE="$(basename "$FILE")"
    BASE="${BASE%.*}"
    DIR="$OUTDIR/$BASE"
    mkdir -p "$DIR"
    PREFIX="$DIR/$BASE"

    echo "[*] Analyzing: $FILE"

    # Report 1: Human-readable packet index
    {
        echo "CAPTURE: $FILE"
        echo "Generated: $(date -Is)"
        echo
        echo "PACKET SUMMARY"
        echo "No. | Time | Length | Source | Destination | Protocol | Info"
        tshark -n -r "$FILE" -t ad \
            -T fields -E header=y -E separator='|' \
            -e frame.number -e frame.time \
            -e frame.len -e _ws.col.Source \
            -e _ws.col.Destination -e _ws.col.Protocol \
            -e _ws.col.Info
    } > "$PREFIX.summary.txt" 2>&1 || {
        echo "[!] Summary export failed: $FILE"
        return 1
    }

    # Report 2: Full decoded protocol dissection
    tshark -n -r "$FILE" -t ad -V \
        > "$PREFIX.details.txt" 2>&1 || {
        echo "[!] Detailed export failed: $FILE"
        return 1
    }

    # Report 3: Packet bytes, including ASCII interpretation
    tshark -n -r "$FILE" -x \
        > "$PREFIX.hex.txt" 2>&1 || {
        echo "[!] Hex export failed: $FILE"
        return 1
    }

    # Report 4: Useful protocol fields, when present
    tshark -n -r "$FILE" \
        -T fields -E header=y -E separator=$'\t' -E quote=d \
        -e frame.number -e frame.time \
        -e ip.src -e ipv6.src -e tcp.srcport -e udp.srcport \
        -e ip.dst -e ipv6.dst -e tcp.dstport -e udp.dstport \
        -e dns.qry.name -e dns.a \
        -e http.request.method -e http.host \
        -e http.request.uri -e http.user_agent \
        -e http.authorization -e http.cookie \
        -e http.file_data \
        -e tls.handshake.extensions_server_name \
        > "$PREFIX.fields.tsv" 2> "$PREFIX.fields-errors.txt" || true

    # Report 5: Extract printable strings from exported hex bytes.
    # This finds visible strings, not encrypted or compressed plaintext.
    if command -v strings >/dev/null 2>&1; then
        strings -a -n 4 "$PREFIX.hex.txt" \
            > "$PREFIX.strings.txt"
    else
        echo "[!] Install binutils for strings extraction."
    fi

    # Report 6: Quick keyword hits across the reports
    grep -Ein -C 2 \
        'password|passwd|pwd|username|user.?name|login|token|secret|api.?key|authorization|cookie|session.?id|bearer|credential|ftp|smtp|http|dns|query' \
        "$PREFIX.details.txt" "$PREFIX.strings.txt" \
        "$PREFIX.fields.tsv" \
        > "$PREFIX.keyword-hits.txt" || true

    echo "[+] Reports saved under: $DIR"
}

if [[ -f "$INPUT" ]]; then
    convert_capture "$INPUT"
else
    while IFS= read -r -d '' FILE; do
        convert_capture "$FILE" || true
    done < <(
        find "$INPUT" -type f \
            \( -iname '*.pcap' -o -iname '*.pcapng' \
            -o -iname '*.cap' -o -iname '*.dmp' \
            -o -iname '*.snoop' -o -iname '*.erf' \) \
            -print0
    )
fi

echo
echo "[+] Analysis finished: $OUTDIR"
