#!/bin/bash
#
# dwf -- initial
# Thu Oct 19 14:35:36 MDT 2023
#

# OpenSSL options (openssl enc -help)
# aes-256-cbc   ciphername
# -e,-d         encrypt,decrypt
# -pbkdf2       password-based key derivation function 2
# -a            output Base-64

QR_ImageDir=${1:-~/Saved/QR_Codes/}

if [ ! -d $QR_ImageDir ]; then
    echo "Edit this script and set 'QR_ImageDir' or supply one"
    echo "Usage: `basename $0` [image_directory]"
    exit 1
fi

#########################################
# extract otpauth uri's from saved images
#########################################
totp-qr --uri ${QR_ImageDir}/* | \
#
#########################################
# encrypt uri's (prompted for a password)
# outputs a Base-64 payload
#########################################
openssl aes-256-cbc -e -pbkdf2 -a | \
#
###############################################
# emit a bash function: totp()
# 1. decrypt the data (prompted for a password)
# 2. send uri's to totp-qr to generate codes
# 3. sort output by issuer
###############################################
perl -0 -ne 'print "\ntotp() {\nopenssl aes-256-cbc -d -pbkdf2 -a << EOF | totp-qr \$1 | sort -t, -k2\n${_}EOF\n}\n"'

exit 0
