docker run --net=host -dt -e NGROK_AUTHTOKEN=<ngrok_token> ngrok/ngrok:latest http 7004
curl http://127.0.0.1:4040/api/tunnels --silent | jq -r .tunnels[].public_url
