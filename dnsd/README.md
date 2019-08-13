# DNSD
`dns_server.py` a python Dynamic Name Server which listens on UDP port 53 for DNS requests. It tries to decode them and if they are valid DNS-sneak, forwards their payload through MQTT.

`dns_coder.py` can be used to code and decode payloads for the DNS-sneak protocol from python.

`dns_sneak_dev.ipynb` was used for development and testing.
