#!/bin/bash
#
# dwf -- initial
# Thu Oct 19 14:35:36 MDT 2023
#

# Initial development script using my cryptopals aes implementation before switching to openssl
# https://github.com/dfarnham/aes
#
# aes options
# -d  decrypt
# -r  random initialization vector (arc4random)
# -c  Cipher Block Chaining
# -a  output Base-64
# -K  2-byte hex characters converted to 16,24,32 bytes
#

# Note the password required to be 64 hex bytes long for aes -256
#
# $> echo foo | sha
# b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c	<stdin>
#
# $> ./scripts/aes.sh images
# enter AES-256-CBC encryption password:
# totp() {
# read -s -p "enter AES-256-CBC decryption password:" password
# echo
# aes --decrypt --randiv --cbc --ibase64 --hexkey $password << EOF | totp-qr $1 | sort -t, -k2
# 4cs3Aqpd/C72h1+PDe1NTh6uQ2UWXdYVj82vaMWA4BtZ6F+Qp4lBTe64myeYY/mZtge9lDr51Oh7
# rMgAzVoPsy8FHD8kdY/5nIypW2awA4u8DbFDR1YXwkTEPcHEU1esamBgeCjw+WkyKZgeyJj88FZP
# JTr1GwEEGqvOUYM/plOBGoTmGw/muH+6IXzUUZ1ktpS2o1wDJ1iZDJYcixGI4F9VdHJfzadYiGIQ
# wc3W1f3HNYOLCguz8Dt89TfC+LkDowgM0NjpX2wR4Qlm+MZ+HvXYCMKO0X1Eqz0c6VzikMvidRBQ
# lFExp1tPME72tVApxGaadtQvkl8Zm2BzILizmgtnnswMq5/hC82x/EGRxJJeU+AjHNPcknR11oKd
# 6bjmO1280UJU3rjp5bh7VDQbetndm6+gQNr6b7B65WMBW5JweguTDdV7qZ/u/K989rZ+QgPyxjq/
# ceohbJKpC6HaMQ==
# EOF
# }


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
aes --encrypt --randiv --cbc --obase64 --hexkey $password | \
#
############################################
# emit a bash function: totp()
# 1. prompt for password, decrypt the data
# 2. send uri's to totp-qr to generate codes
# 3. sort output by issuer
############################################
perl -0 -ne 'print "\ntotp() {\nread -s -p \"enter AES-256-CBC decryption password:\" password\necho\naes -drAcK \$password << EOF | totp-qr \$1 | sort -t, -k2\n${_}EOF\n}\n"'

exit 0
