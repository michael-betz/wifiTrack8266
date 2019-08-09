#include "ESP8266WiFi.h"
extern "C" {
	#include "dns_sneaker.h"
}

void setup()
{
	Serial.begin(115200);
	// Set WiFi to station mode and disconnect from an AP if it was previously connected
	WiFi.mode(WIFI_STA);
	WiFi.disconnect();
}

void loop()
{
	char host_buf[DNS_REQUEST_BUFFER_SIZE(255)];
	char pl_buf[256];
	IPAddress ip_res;
	// WiFi.scanNetworks will return the number of networks found
	int n = WiFi.scanNetworks();
	String best_ssid = "";
	int best_rssi = -9999;
	for (int i = 0; i < n; i++) {
		// Print SSID and RSSI for each network found
		Serial.print(WiFi.encryptionType(i)); Serial.write(';');
		Serial.print(WiFi.SSID(i)); Serial.write(';');
		Serial.print(WiFi.RSSI(i)); Serial.write(';');
		Serial.write('\n');
		// Look out for a connectable network
		if ((WiFi.encryptionType(i) == ENC_TYPE_NONE) && (WiFi.RSSI(i) > best_rssi)) {
			best_rssi = WiFi.RSSI(i);
			best_ssid = WiFi.SSID(i);
		}
	}
	if (best_rssi > -9999) {
		Serial.printf("Connecting to %s (%d) ", best_ssid.c_str(), best_rssi);
		WiFi.begin(best_ssid, "");
		for (int i = 0; i < 100; i++) {
			delay(100);
			if (WiFi.status() == WL_CONNECTED) {
				Serial.print("got IP!!!\n");
				sprintf(pl_buf, "%lu", millis());
				dnsEncode((uint8_t*)pl_buf, strlen(pl_buf), (uint8_t*)host_buf);
				WiFi.hostByName(host_buf, ip_res, DNS_TIMEOUT);
				Serial.print(ip_res);
				break;
			}
		}
		WiFi.disconnect();
	} else {
		Serial.print("No open wifi found :(\n");
		return;
	}
	Serial.print("\n\n");
	delay(30000);
}
