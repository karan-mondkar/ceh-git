
#!/bin/sh

# CEH DNS Domain / DNS Tree Name Finder

if [ "$#" -ne 1 ]; then
    echo "Usage: sh h.sh <target-IP>"
    exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
    echo "Error: Nmap is not installed."
    exit 1
fi

nmap -n -Pn -p 3389 --script rdp-ntlm-info "$1"
