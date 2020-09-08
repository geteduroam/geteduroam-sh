# geteduroam shell client

An sh client for retrieving a geteduroam eap-config file

This script is a shell implementation of the [geteduroam API](https://www.geteduroam.app/developer/api/)

On first run, the script will listen to a random port (does not check if it is available, just restart if it isn't) on 127.0.0.1,
and work as an OAuth client.  When an access_token is obtained, it will be used to download an eap_config file.

If a refresh_token is obtained, it is written to `.geteduroam-refresh-HASH`, where `HASH` is based on the token_url.
When reconnecting to a token_url where a refresh_token is available, the script will try the refresh token before listening for a webbrowser.

The script does not use the discovery on https://discovery.eduroam.app/v1/discovery.json and it is not able to install the downloaded eap-config.
