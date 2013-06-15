#!/bin/bash

DEBUG=0

# Parse parameters:
# -H hostname        Hostname (required)
# -c file            Client certificate file (optional)
# -k file            Client private key file (optional)
# -P string          Password for decrypt client private key file (optional)
# -u url             Absolute URL (optional, default 'https://hostname/')
# -p port            Port (optional, default 443)
# -e days            Check Server certificate expiration (optional)
#                    warning if there are less than n days to expiration

is_integer() {
   local min="$2"
   local max="$3"

   if ! [[ "$1" =~ ^[0-9]+$ ]] ; then
      return 1
   fi

   if [ -n "$2" ] && [ $2 -gt $1 ]; then return 1; fi
   if [ -n "$3" ] && [ $3 -lt $1 ]; then return 1; fi

   return 0
}

is_ip() {
   case "$*" in
      ""|*[!0-9.]*|*[!0-9]) return 1 ;;
   esac

   local IFS=.
   set -- $*

   [ $# -eq 4 ] &&
   [ ${1:-666} -le 255 ] && [ ${2:-666} -le 255 ] &&
   [ ${3:-666} -le 255 ] && [ ${4:-666} -le 254 ]
}

is_fqdn() {
   if is_ip "$1"; then return 0; fi
   echo "$1" | egrep -q "^([a-zA-Z0-9_\-]{1,63}\.?)+([a-zA-Z]{2,})$"
#   echo "$1" | egrep -q "(?=^.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.?)+(?:[a-zA-Z]{2,})$)"
}

roolback() {
   /bin/rm -rf "$OUTPUT_DIR"
}

OPENSSL_BIN='/usr/bin/openssl'
OPENSSL_CLIENT="$OPENSSL_BIN s_client"
AWK_BIN='/usr/bin/awk'
OUTPUT_DIR=/tmp/chcc_$$
CA_PATH='/etc/ssl/certs'

trap "{ roolback; }" EXIT

NAGIOS_OK=0
NAGIOS_WARNING=1
NAGIOS_CRITICAL=2

# Check environment

if [ ! -x "$OPENSSL_BIN" ]; then
   echo "CRITICAL: OpenSSL is not installed"
   exit $NAGIOS_CRITICAL
fi

if [ ! -x "$AWK_BIN" ]; then
   echo "CRITICAL: Awk is not installed"
   exit $NAGIOS_CRITICAL
fi

if [ ! -d "$CA_PATH" ]; then
   echo "CRITICAL: Common CA Certificates path not found. Maybe ca-certificates package is not installed"
   exit $NAGIOS_CRITICAL
fi

HOSTNAME=
CLIENT_CERT=
CLIENT_KEY=
CLIENT_KEY_PASS=
PORT=443
CHECK_EXPIRATION=0

# Parse params
while getopts ":H:c:k:P:u:p:e:" optname; do
   case "$optname" in
      "H") HOSTNAME="$OPTARG" ;;
      "c") CLIENT_CERT="$OPTARG" ;;
      "k") CLIENT_KEY="$OPTARG" ;;
      "P") CLIENT_KEY_PASS="$OPTARG" ;;
      "p") PORT="$OPTARG" ;;
      "e") CHECK_EXPIRATION="$OPTARG" ;;
      "?") echo "WARNING: Unknown option $OPTARG"; exit $NAGIOS_WARNING ;;
      ":") echo "WARNING: No argument value for option $OPTARG"; exit $NAGIOS_WARNING ;;
      *)   echo "WARNING: Unknown error while processing options"; exit $NAGIOS_WARNING ;;
   esac
done

if [ $DEBUG -eq 1 ]; then
   echo "HOSTNAME          = $HOSTNAME"
   echo "CLIENT_CERT       = $CLIENT_CERT"
   echo "CLIENT_KEY        = $CLIENT_KEY"
   echo "CLIENT_KEY_PASS   = $CLIENT_KEY_PASS"
   echo "URL               = $URL"
   echo "PORT              = $PORT"
   echo "CHECK_EXPIRATION  = $CHECK_EXPIRATION"
fi

# Check parameters

if [ -z "$HOSTNAME" ]; then
   echo "CRITICAL: Hostname is required"
   exit $NAGIOS_CRITICAL
fi

if ! is_fqdn "$HOSTNAME"; then
   echo "CRITICAL: Hostname is not a Full Qualified Domian Name (FQDN)"
   exit $NAGIOS_CRITICAL
fi

if [ -n "$CLIENT_CERT" ] && [ ! -e "$CLIENT_CERT" ]; then
   echo "CRITICAL: Client certificate file not found"
   exit $NAGIOS_CRITICAL
fi

if [ -n "$CLIENT_CERT" ] && [ ! -e "$CLIENT_KEY" ]; then
   echo "CRITICAL: Client private key file not found"
   exit $NAGIOS_CRITICAL
fi

if ! is_integer "$CHECK_EXPIRATION"; then
   echo "CRITICAL: Expiration must be a number of days"
   exit $NAGIOS_CRITICAL
fi

mkdir -p "$OUTPUT_DIR"

OPTIONAL=
if [ -n "$CLIENT_CERT" ]; then
   OPTIONAL="$OPTIONAL -cert '$CLIENT_CERT'"
fi

if [ -n "$CLIENT_KEY" ]; then
   OPTIONAL="$OPTIONAL -key '$CLIENT_KEY'"
fi

if [ -n "$CLIENT_KEY_PASS" ]; then
   OPTIONAL="$OPTIONAL -pass:$CLIENT_KEY_PASS"
fi

# Check connection
if [ $DEBUG -eq 1 ]; then
   echo "Executing : $OPENSSL_CLIENT $OPTIONAL -connect $HOSTNAME:$PORT -CApath '$CA_PATH'"
fi

echo | $OPENSSL_CLIENT $OPTIONAL -connect $HOSTNAME:$PORT -CApath "$CA_PATH" > "$OUTPUT_DIR/stdout.log" 2> "$OUTPUT_DIR/stderr.log"
error=$?

status=$NAGIOS_CRITICAL
message=

if [ $error -eq 0 ]; then
   verifymsg=`cat "$OUTPUT_DIR/stdout.log" | grep "Verify"`
   read -rd '' verifymsg <<< "$verifymsg"
   if echo "$verifymsg" | grep -q "ok"; then
      message="OK: SSL connection established and verified"
      status=$NAGIOS_OK
   else
      message="WARNING: SSL connection established but not verified ($verifymsg)"
      status=$NAGIOS_WARNING
   fi
else
   errmsg=`tail -n 1 "$OUTPUT_DIR/stderr.log"`
   message="CRITICAL: Can not establish SSL connection ($errmsg)"
   status=$NAGIOS_CRITICAL
fi

if [ $CHECK_EXPIRATION -gt 0 ]; then
   # Check expiration
   $AWK_BIN 'BEGIN { insidecert=0 };\
       /-----BEGIN CERTIFICATE-----/ { insidecert=1 };\
       {if (insidecert) { print $0 }}; \
       /-----END CERTIFICATE-----/ { insidecert=0 }' < "$OUTPUT_DIR/stdout.log" > "$OUTPUT_DIR/server.pem"
   expdate=`$OPENSSL_BIN x509 -noout -enddate -in "$OUTPUT_DIR/server.pem" | sed 's/.*=\([^\/]*\).*/\1/g'`
   cn=`$OPENSSL_BIN x509 -noout -subject -in "$OUTPUT_DIR/server.pem" | sed 's/.*CN=\([^\/]*\).*/\1/g'`

   if [ $DEBUG -eq 1 ]; then
      echo "Expiration date : $expdate"
   fi

   now=`date '+%s'`
   exp=`date -d"$expdate" '+%s'`
   diff=$((exp - now))
   days=$((diff / 86400))
   limit=$((CHECK_EXPIRATION * 86400))
   limit=$((now + limit))

   if [ $now -gt $exp ]; then
      message="CRITICAL: Certificate '$cn' is expired ($expdate)"
      status=$NAGIOS_CRITICAL
   elif [ $limit -gt $exp ]; then
      message="WARNING: Certificate '$cn' will expired in $days days ($expdate)"
      status=$NAGIOS_CRITICAL
   else
      message="OK: Certificate '$cn' will expire on $expdate"
      status=$NAGIOS_OK
   fi

fi

echo "$message"
exit $status
