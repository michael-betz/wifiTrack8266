// Send a Hello World message to the DNS server for testing

#include "ESP8266WiFi.h"
extern "C" {
	#include "dns_sneaker.h"
}
#include "secrets.h"

#define DNS_URL_POSTFIX ".dnsr.uk.to"

void hex_dump(uint8_t *buffer, unsigned len) {
	for(unsigned i=0; i<len; i++) {
		if ((len > 16) && ((i % 16) == 0)) {
			Serial.printf("\n    %04x: ", i);
		}
		Serial.printf("%02x ", *buffer++);
	}
	Serial.printf("\n");
}

void setup()
{
	Serial.begin(115200);
	// Set WiFi to station mode and disconnect from an AP if it was previously connected
	WiFi.mode(WIFI_STA);
	WiFi.disconnect();

	// AES secret key
	static const uint8_t sk[16] = SECRET_KEY;

	// Base32 alphabet lookup table
	static const char g_cod_tbl[] = CODING_TABLE;

	// AES initial vector
	static uint32_t iv[4];
	for(unsigned i=0; i<4; i++)
		iv[i] = RANDOM_REG32;

	encode_dns_init(sk, (uint8_t*)iv, g_cod_tbl);
}

void loop()
{
	char host_buf[256];
	uint8_t pl_buf[256];
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
				sprintf((char*)pl_buf, "Hello World, ts = %d ms", millis());
				encode_dns(pl_buf, strlen((char*)pl_buf), host_buf);
				strcat(host_buf, DNS_URL_POSTFIX);
				WiFi.hostByName(host_buf, ip_res, 5000);
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
