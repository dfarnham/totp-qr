#!/bin/bash
#
# dwf -- initial
# Thu Oct 19 14:35:36 MDT 2023
#

# Initial development script using my cryptopals aes implementation before switching to openssl
# https://github.com/dfarnham/aes
#

QR_ImageDir=${1:-~/Saved/QR_Codes/}

if [ ! -d $QR_ImageDir ]; then
    echo "Edit this script and set 'QR_ImageDir' or supply one"
    echo "Usage: `basename $0` [image_directory]"
    exit 1
fi

# prompt for password
read -s -p "enter AES-256-CBC encryption password:" password

#########################################
# extract otpauth uri's from saved images
#########################################
totp-qr --uri ${QR_ImageDir}/* | \
#
#########################################
# encrypt uri's, output a Base-64 payload
#########################################
aes -e --aes-256-cbc --pbkdf2 -a -k $password | \
#
############################################
# emit a bash function: totp()
# 1. prompt for password, decrypt the data
# 2. send uri's to totp-qr to generate codes
# 3. sort output by issuer
############################################
perl -0 -ne 'print "\ntotp() {\nread -s -p \"enter AES-256-CBC decryption password:\" password\necho\naes -d --aes-256-cbc --pbkdf2 -A -k \$password << EOF | totp-qr \$1 | sort -t, -k2\n${_}EOF\n}\n"'

exit 0
