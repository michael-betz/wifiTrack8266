# wifiTrack

This project is all about doing geolocation in a sneaky way.

The ESP8266's wifi allows to get a list of nearby access points. This information is collected periodically and sent back home through open wifi access points. The ability of many public hotspots to carry out geniue DNS requests is exploited to relay back information to an internet server. The actual geolocation is carried out there, utilizing the Google or Mozilla geolocation APIs.

It seems like the `DNS-sneak` protocol on ESP8266 is a good match for extremely low-cost autonomous sensor nodes.
Especially in urban environments with many public hot-spots this might be a good alternative to using LORA radio.

# Instructions

`lib/dns_sneaker` contains the library for coding data into DNS names.

`lib/dns_sneaker/test` contains a test-bench which can be built with `make` and ran on linux.

`pio run -t upload -t monitor` to program the ESP8266. I'm using a nodemcu board with integrated USB connection.

`dnsd` contains the server part, which runs all on python. Make sure your ISP does not block UDP port 53.
