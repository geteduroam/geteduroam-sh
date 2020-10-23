#!/bin/sh
# Client for retrieving eap-config from geteduroam server
#
# Copyright (c) 2019-2020 Jørn Åne de Jong
#
# LICENSE: BSD-3-Clause
# http://opensource.org/licenses/BSD-3-Clause

if [ -z $1 ]
then
	printf '\033[0musage: %s base-url [realm]\n\nexample: \033[1m%s "http://[::1]:1080" demo.eduroam.no >eduroam.eap-config\033[0m\n\nPlease note: base-url must be available from both your webbrowser and this script,\nuse -R1080:localhost:1080 if you want to test a local server from remote\n\n' "$0" "$0" >&2
	exit 2
fi

# On MacOS, use the system browser
[ -x /usr/bin/open ] && BROWSER=/usr/bin/open

URL="$1"
SCOPE="eap-metadata"
PORT="0$3"
while [ $PORT -lt 1024 -o $PORT -gt 65535 ]
do
	PORT=$RANDOM
	[ -z "$PORT" ] && PORT=$(tr -cd '0123456789' </dev/urandom | head -c5)
done
PORT=$(printf "%s" $PORT | sed -es/\^0\*//)
CLIENT_ID="app.geteduroam.sh"

# nc may not be able to listen on IPv6,
# but IPv4 works virtually always
REDIRECT_URI="http://127.0.0.1:$PORT/"

if [ -n "$2" ]
then
	REALM_PARAM="?realm=$2"
fi
[ "$(printf "%s" "$URL" | head -c8)" == 'https://' ] \
	|| [ "$(printf "%s" "$URL" | head -c7)" == 'http://' ] \
	|| URL="https://$URL"

AUTHORIZE_URL="$URL/oauth/authorize/$REALM_PARAM"
TOKEN_URL="$URL/oauth/token/$REALM_PARAM"
GENERATE_URL="$URL/api/eap-config/$REALM_PARAM"
REFRESH_TOKEN_FILENAME=".geteduroam-refresh-$(printf "%s" "$TOKEN_URL" | openssl sha256 | tail -c16)"

CODE_VERIFIER="$(LC_ALL=C tr -cd '[:alnum:]-_.~' </dev/urandom | head -c128)"
STATE="$(LC_ALL=C tr -cd '[:alnum:]_-' </dev/urandom | head -c43)"

urlb64() {
	openssl base64 | sed -es@/@_@g -es@+@-@g -es@=@@
}
sha256bin() {
	# xxd is in MacOS base, but so is OpenSSL..
	#shasum -a256 | head -c64 | xxd -r -p
	openssl sha256 -binary
}
urlToQuery() {
	# Get the query part of the URL,
	# aka show everything from the first question mark until the first space
	cut -d\? -f2 | cut -d\  -f1
}
getQuery() { # $1 = key
	# tr: Convert foo=bar&pie=good to foo=bar\npie=good
	# grep: takes the correct line
	# head: ensure no double matches
	# cut: remove the key so only the value remains
	tr \& \\n | grep --fixed-strings "${1}=" | head -n1 | cut -d= -f2-
}
getJson() { # $1 = key
	if jq --version 2>&1 >/dev/null
	then
		jq --raw-output ".$1"
	elif json_pp -v 2>&1 >/dev/null
	then
		# This is not a reliable JSON parser, we still get JSON escaped strings,
		# and multiline would fail horribly.
		# But it's good enough for our use.
		json_pp | grep --fixed-strings "   \"${1}\" : " | cut -d\" -f4- | sed -e's/",\{0,1\}$//'
	fi
}
listen() { # $1 = port
	# We're not sure if we have GNU Linux or BSD nc, and it's not easy to probe either
	# but we can try the GNU Linux version first, with flags that will make the BSD
	# version terminate rightaway
	nc -q1 -lp "$1" 2>/dev/null || nc -l "$1"
}
fifo() {
	if [ \! -p fifo ]
	then
		mkfifo fifo
	fi
	cat fifo
}
trap "rm fifo" EXIT

serve() {
	[ -p fifo ] || mkfifo fifo
	answered=0
	fifo | listen $PORT | while read line
	do
		# We got a response, show this message in case we get stuck
		window 'Closing connection' "Response received, but we're stuck, refresh your browser"
		# If we aren't actually stuck the message won't appear long enough for the user to read

		# We get stuck when nc doesn't quit after receiving an EOF on the fifo,
		# which is implicitly sent upon redirecting the printf (or any other) output there
		# so we have to convince the browser to close the TCP connection
		# Only the Linux version of nc seems to be able to get stuck

		error="$(printf "%s" "$line" | urlToQuery | getQuery error)"
		if [ -n "$error" ]
		then
			if [ "$error" = 'access_denied' ]
			then
				printf 'HTTP/1.0 403 Forbidden\r\nContent-Type: text/plain\r\n\r\n%s\r\n' "$error" >fifo
				window 'Access denied' "$(printf '\033[31mThe user refused access to this application, press ^C to exit')"
			else
				printf 'HTTP/1.0 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\n%s\r\n' "$error" >fifo
				window 'Error' "$(printf '\033[31mAn unexpected error occurred: \033[1m%s\033[0;31m, press ^C to exit' "$error")"
			fi
		else
			printf "%s" "$line" | urlToQuery
			# We lie about the Content-Length (we report two bytes less, the CRLF)
			# so the browser will hopefully disconnect, this will speed up the process
			# because nc will terminate quicker
			printf 'HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 28\r\n\r\nAll done! Close browser tab.\r\n' >fifo
		fi
		break
	done
}

redirect() { # $1 = url
	fifo | listen $PORT | while read line
	len=$(printf "%s" "$1" | wc -c)
	do
		# We lie about the Content-Length (we report two bytes less, the CRLF)
		# so the browser will hopefully disconnect, this will speed up the process
		# because nc will terminate quicker
		printf 'HTTP/1.0 302 Found\r\nLocation: %s\r\nContent-Length: %s\r\n\r\n%s\r\n' "$1" "$len" "$1" >fifo
		break
	done
}

window() { # $1 = title, $2 = text
	printf '\033[A\033[A\033[A\033[A\033[F\033\033[1;44;37m\n • %s\033[K\033[0;47;30m\n\033[K\n   %s\033[K\n\033[K\033[0m\n' "$1" "$2" >&2
}

set -e

[ -f "$REFRESH_TOKEN_FILENAME" ] && refresh_token="$(cat "$REFRESH_TOKEN_FILENAME")"

if [ "$(echo '{"foo":"test"}' | getJson foo)" != 'test' ]
then
	printf '\033[1;41;37m Missing JSON parser   \033[0m\n\033[47;30m Tried \033[34mjq\033[30m and \033[34mjson_pp\033[30m. \033[0m\n\n'
	exit 2
fi

if [ -n "$refresh_token" ]
then
	token_data="$(curl \
		--fail \
		--silent \
		--show-error \
		-HAccept:application/json \
		--data-urlencode "client_id=$CLIENT_ID" \
		--data-urlencode "redirect_uri=$REDIRECT_URI" \
		--data-urlencode grant_type=refresh_token \
		--data-urlencode "refresh_token=$refresh_token" \
		"$TOKEN_URL")" || true
	access_token=$(printf "%s" "$token_data" | getJson access_token)
	refresh_token=$(printf "%s" "$token_data" | getJson refresh_token)
fi

printf '\n\n\n\n\n' >&2
if [ -z "$access_token" ]
then
	code_challenge="$(printf "$CODE_VERIFIER" | sha256bin | urlb64)"
	separator=$(printf "%s" "$AUTHORIZE_URL" | grep --fixed-strings --quiet '?' && printf '&' || printf '?')
	authorize_url="${AUTHORIZE_URL}${separator}response_type=code&code_challenge_method=S256&scope=$SCOPE&code_challenge=$code_challenge&redirect_uri=$REDIRECT_URI&client_id=$CLIENT_ID&state=$STATE"
	[ -n "$BROWSER" ] && "$BROWSER" "$REDIRECT_URI" || \
		window 'Please visit the following URL in your webbrowser' "$(printf "\033[4;34m$REDIRECT_URI")"
	redirect "$authorize_url"
	window 'Please log in and approve this application in your webbrowser' 'Waiting for response...'
	code=
	while [ -z "$code" ]
	do
		response="$(serve)"
		window 'Please wait' 'Parsing response'
		code="$(printf "%s" $response | getQuery code)"
		state="$(printf "%s" $response | getQuery state)"
	done

	# We have received an access token, so we must assume our refresh_token is burned (if we used one)
	rm -f "$REFRESH_TOKEN_FILENAME"

	window 'Please wait' "Fetching token from $TOKEN_URL"
	token_data="$(curl \
		--fail \
		--silent \
		--show-error \
		-HAccept:application/json \
		--data-urlencode "client_id=$CLIENT_ID" \
		--data-urlencode "redirect_uri=$REDIRECT_URI" \
		--data-urlencode grant_type=authorization_code \
		--data-urlencode "code=$code" \
		--data-urlencode "code_verifier=$CODE_VERIFIER" \
		"$TOKEN_URL")"
	access_token=$(printf "%s" "$token_data" | getJson access_token)
	refresh_token=$(printf "%s" "$token_data" | getJson refresh_token)
fi

window 'Please wait' "Fetching eap-config from $GENERATE_URL"
curl --fail --silent --show-error -HAuthorization:"Bearer $access_token" -d '' "$GENERATE_URL"

printf '\n\n\n\n\n' >&2
window 'Success' 'Successfully downloaded eap-config file'

if [ -n "$refresh_token" ]
then
	printf "%s" "$refresh_token" > "$REFRESH_TOKEN_FILENAME"
fi
