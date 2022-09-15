#!/bin/bash


# Interactive Shell script to encrypt messages

# This script uses python source file - to use it with binary package,
# substitute this part of command (line 30):
#
# python2 ECcrypt-CLI.py
#
# with this:
# ./ECcrypt-CLI

# Create temporary file to store plain text
femb1="$(mktemp)"

# Message is entered in the terminal
printf 'Enter multiline text message to encrypt [finish input by Ctrl+D]:\n'
cat > $femb1

# Reading MasterKey ID
printf 'Enter ID of a MasterKey to encrypt with:\n'
read mkey

# Reading Contact IDs
printf 'Enter IDs of Contacts to encrypt for, separated by a single space:\n'
read cont

# Main command
python2 ECcrypt-CLI.py encrypt --master-key $mkey --contact-id $cont --msg $femb1 

# Removing temporary files
rm -f $femb1

# Notifying that temporary files are deleted
printf '\n\n\nDeleted %s \n\n' "$femb1"
