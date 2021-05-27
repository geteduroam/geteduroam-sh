#!/bin/sh
# eap-config installer
#
# Copyright (c) 2019-2021 Jørn Åne de Jong
#
# LICENSE: BSD-3-Clause
# http://opensource.org/licenses/BSD-3-Clause

set -e

wifi_if="wlan0"  # todo auto-detect somehow
xml="$(sed -e 's/^[[:space:]]*//' <"$1" | tr -d \\r\\n)" # read XML, remove all newlines
mkdir -p ~/.config/geteduroam

get_first_tag_content() { # $1 = tag, stdin=XML
	tag="$1"
	# remove anything after </$tag> so only the first one is returned
	sed -e "s@</${tag}>.*@@" | get_tag_content "$tag"
}

get_tag_content() { # $1 = tag, stdin=XML
	tag="$1"
	# on MacOS Mojave we found that sed cannot use \n in the replacement,
	# so we replace with \r instead and then use tr to convert \r to \n

	# assume input is one line
	# add newline before <$tag> or <$tag foo="blabla">
	# add newline after </$tag>
	# grep for <$tag> or <$tag foo="blabla"> (remove lines without it)
	# remove <$tag>, </$tag> and <$tag foo="blabla">
	sed -e "s@<${tag}[^>]*>@"$'\r'"<${tag}>@g" -e "s@</${tag}>@</${tag}>"$'\r'"@g" \
		| tr '\r' '\n' \
		| grep "<${tag}.*>." \
		| sed -e "s@^<${tag}[^>]*>@@" -e "s@</${tag}>\$@@"
}

parse_auth_method() { # $1= get_tag_content AuthenticationMethod
	authMethod="$1"
	outerEap="$(printf %s "$authMethod" \
		| get_first_tag_content EAPMethod \
		| get_first_tag_content Type)"
	innerEap="$(printf %s "$authMethod" \
		| get_first_tag_content InnerAuthenticationMethod \
		| get_first_tag_content EAPMethod \
		| get_first_tag_content Type)"
	innerNonEap="$(printf %s "$authMethod" \
		| get_first_tag_content InnerAuthenticationMethod \
		| get_first_tag_content NonEAPAuthMethod \
		| get_first_tag_content Type)"

	#printf "Outer: $outerEap\n"
	#printf "Inner: $innerEap\n"
	#printf "NonEAP $innerNonEap\n"

	case "$outerEap" in
		13)
			printf 'TLS';return
		;;
		21)
			case "$innerEap" in
				26) printf 'TTLS-EAP-MSCHAPv2\n';return;;
			esac
			case "$innerNonEap" in
				1) printf 'TTLS-PAP\n';return;;
				2) printf 'TTLS-MSCHAP\n';return;;
				3) printf 'TTLS-MSCHAPv2\n';return;;
			esac
		;;
		25)
			case "$innerEap" in
				26) printf 'PEAP-MSCHAPv2\n';return;;
			esac
		;;
	esac
}

# Collect variables from eap-config file
ssids="$(printf %s "$xml" | get_tag_content SSID)"
mainssid="$(printf %s "$ssids" | head -n1)"
if test -z "$mainssid"
then
	printf 'No SSIDs provided\n'
	exit 1
fi


# Find out which authentication method we're going to use
authMethod="$(printf %s "$xml" | get_tag_content AuthenticationMethod | while read -r authMethod
do
	method="$(cat)"
	type="$(printf %s "$method" | parse_auth_method "$authMethod")"
	if test -n "$type"
	then
		printf %s "$authMethod"
		true >~/.config/geteduroam/ca-"$mainssid".pem
		printf %s "$method" | get_tag_content ServerSideCredential | get_tag_content CA | while read -r ca
		do
			printf -- '-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n' "$ca" >>~/.config/geteduroam/ca-"$mainssid".pem
		done
		break
	fi
done)"
type="$(parse_auth_method "$authMethod")"
server_ids="$(printf %s "$authMethod" | get_tag_content ServerID)"
test -n "$type" || { printf %s\\n 'Unsupported eap-config' >&2; exit 2; }


# Collect non-TLS authentication parameters
if test 'TLS' != "$type"
then
	suffix="$(printf %s "$authMethod" | get_tag_content InnerIdentitySuffix)"
	hint="$(printf %s "$authMethod" | get_tag_content InnerIdentityHint)"
	test -z "$hint" || suffix="@$suffix"
	username="$(printf %s "$authMethod" | get_tag_content UserName)"
	while true
	do
		printf 'Username: '
		test -n "$username" || read -r username
		case "$username" in
			*"$suffix")
				break
			;;
			*)
				username=
				printf 'Username must end with %s\n' "$suffix"
			;;
		esac
	done

	#	# TODO: figure out how to set password through nmcli
	#	password="$(printf %s "$authMethod" | get_tag_content Password)"
	#	test -n "$password" || printf 'Password: '
	#	# shellcheck disable=SC2039
	#	# We try to use "secret" but if it doesn't work we have a fallback
	#	test -n "$password" || read -sr password 2>/dev/null
	#	test -n "$password" || printf '\rWARNING: Password will print on screen\nPassword: '
	#	test -n "$password" || read -r password
fi

identity="$(printf %s "$xml" | get_tag_content OuterIdentity)"
test -n "$identity" || identity="$username"

passphrase="$(printf %s "$xml" | get_tag_content Passphrase)"

mask="$(umask)"
umask 077
printf %s "$xml" | get_tag_content ClientCertificate | base64 --decode >~/.config/geteduroam/tmp-"$mainssid".p12
umask "$mask"
if test -s ~/.config/geteduroam/tmp-"$mainssid".p12
then
	pass="$(test -n "$passphrase" && printf -- '-passin pass:%s -passout pass:%s' "$passphrase" "$passphrase" || printf -- -nodes)"
	# shellcheck disable=SC2086
	# We explicitly use $pass for multiple arguments
	openssl pkcs12 $pass -in ~/.config/geteduroam/tmp-"$mainssid".p12 -out ~/.config/geteduroam/cert-"$mainssid".pem -clcerts -nokeys 2>/dev/null
	# shellcheck disable=SC2086
	# We explicitly use $pass for multiple arguments
	openssl pkcs12 $pass -in ~/.config/geteduroam/tmp-"$mainssid".p12 -out ~/.config/geteduroam/key-"$mainssid".pem -nocerts 2>/dev/null
fi
rm -f ~/.config/geteduroam/tmp-"$mainssid".p12


# install profile
for ssid in $ssids
do
	case "$type" in
		'TLS')
			nmcli connection add \
				type wifi \
				con-name "$ssid" \
				ifname "$wifi_if" \
				connection.permissions cms \
				ssid "$ssid" \
				wifi-sec.key-mgmt wpa-eap \
				802-1x.eap tls \
				802-1x.altsubject-matches "$server_ids" \
				802-1x.ca-cert ~/.config/geteduroam/ca-"$mainssid".pem \
				802-1x.tmp-cert ~/config/geteduroam/cert-"$mainssid".pem \
				802-1x.private-key-password "$passphrase" \
				802-1x.private-key ~/.config/geteduroam/key-"$mainssid".pem \

		;;
		'TTLS-PAP')
			nmcli connection add \
				type wifi \
				con-name "$ssid" \
				ifname "$wifi_if" \
				ssid "$ssid" \
				wifi-sec.key-mgmt wpa-eap \
				802-1x.eap ttls \
				802-1x.phase2-auth pap \
				802-1x.identity "$username" \
				802-1x.anonymous-identity "$identity" \
				802-1x.altsubject-matches "$server_ids" \
				802-1x.ca-cert ~/.config/geteduroam/ca-"$mainssid".pem \

		;;
		'TTLS-MSCHAP')
			nmcli connection add \
				type wifi \
				con-name "$ssid" \
				ifname "$wifi_if" \
				ssid "$ssid" \
				wifi-sec.key-mgmt wpa-eap \
				802-1x.eap ttls \
				802-1x.phase2-auth mschap \
				802-1x.identity "$username" \
				802-1x.anonymous-identity "$identity" \
				802-1x.altsubject-matches "$server_ids" \
				802-1x.ca-cert ~/.config/geteduroam/ca-"$mainssid".pem \

		;;
		'TTLS-MSCHAPv2')
			nmcli connection add \
				type wifi \
				con-name "$ssid" \
				ifname "$wifi_if" \
				ssid "$ssid" \
				wifi-sec.key-mgmt wpa-eap \
				802-1x.eap ttls \
				802-1x.phase2-auth mschapv2 \
				802-1x.identity "$username" \
				802-1x.anonymous-identity "$identity" \
				802-1x.altsubject-matches "$server_ids" \
				802-1x.ca-cert ~/.config/geteduroam/ca-"$mainssid".pem \

		;;
		'TTLS-EAP-MSCHAPv2')
			nmcli connection add \
				type wifi \
				con-name "$ssid" \
				ifname "$wifi_if" \
				ssid "$ssid" \
				wifi-sec.key-mgmt wpa-eap \
				802-1x.eap ttls \
				802-1x.phase2-auth eap-mschapv2 \
				802-1x.identity "$username" \
				802-1x.anonymous-identity "$identity" \
				802-1x.altsubject-matches "$server_ids" \
				802-1x.ca-cert ~/.config/geteduroam/ca-"$mainssid".pem \

		;;
		'PEAP-MSCHAPv2')
			nmcli connection add \
				type wifi \
				con-name "$ssid" \
				ifname "$wifi_if" \
				ssid "$ssid" \
				wifi-sec.key-mgmt wpa-eap \
				802-1x.eap peap \
				802-1x.phase2-auth mschapv2 \
				802-1x.identity "$username" \
				802-1x.anonymous-identity "$identity" \
				802-1x.altsubject-matches "$server_ids" \
				802-1x.ca-cert ~/.config/geteduroam/ca-"$mainssid".pem \

		;;
	esac
done
