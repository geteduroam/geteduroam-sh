# geteduroam shell client

An sh client for retrieving a geteduroam eap-config file

This script is a shell implementation of the [geteduroam API](https://www.geteduroam.app/developer/api/)

On first run, the script will listen to a random port (does not check if it is available, just restart if it isn't) on 127.0.0.1,
and work as an OAuth client.  When an access_token is obtained, it will be used to download an eap_config file.

If a refresh_token is obtained, it is written to `.geteduroam-refresh-HASH`, where `HASH` is based on the token_url.
When reconnecting to a token_url where a refresh_token is available, the script will try the refresh token before listening for a webbrowser.

The script does not use the discovery on https://discovery.eduroam.app/v1/discovery.json and it is not able to install the downloaded eap-config.


## Using the script remotely

Set up the SSH connection with a local port forward, `-L8080:localhost:8080`, so your SSH client will expose port 8080 on the remote to your local machine.  This allows the local browser to connect to the script running remote.


### Testing a locally running geteduroam server

Also set up a remote port forward, if you run the geteduroam server on port 1080, use `-R1080:localhost:1080`, so your SSH client will expose your local port 1080 to the remote host.
