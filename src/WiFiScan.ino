// Send a Hello World message to the DNS server for testing
extern "C" {
	#include "dns_sneaker.h"
}
#include "ESP8266WiFi.h"
#include "secrets.h"
#include <algorithm>
using namespace std;

#define DNS_URL_POSTFIX ".dnsr.uk.to"
#define PID_SSID 0x00

// For keeping index + rssi number together while sorting
struct t_rssi_ind {
	unsigned index;
	int rssi;
};

struct __attribute__ ((packed)) t_payload_header {
	uint8_t rssi_n;

	int rssi;
};

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

// index 0 will have the strongest wifi
bool rssi_comp(const t_rssi_ind &left, const t_rssi_ind &right) {
	return left.rssi > right.rssi;
}

#define MAX_WIFIS 64
unsigned wifi_eval(int n_wifis, uint8_t *buf, unsigned buf_len)
{
	t_rssi_ind rssis[MAX_WIFIS];
	const int n_max = min(n_wifis, MAX_WIFIS);

	// Fetch all RSSIs and sort them, strongest at index [0]
	for (int i=0; i<n_max; i++) {
		rssis[i].rssi = WiFi.RSSI(i);
		rssis[i].index = i;
	}
	sort(rssis, rssis + n_max, rssi_comp);

	// Create DNS payload
	unsigned pl_len = 0;
	*buf++ = PID_SSID;
	pl_len++;
	for (int i=0; i<n_max; i++) {
		uint8_t rssi = (uint8_t)(-rssis[i].rssi);	 // len = 1 [-dBm]
		uint8_t *bssid = WiFi.BSSID(rssis[i].index); // len = 6
		// ssid len 								 // len = 1
		// String ssid = WiFi.SSID(rssis[i].index);  	 // len <= 32
		unsigned group_len = 1 + 6; // + 1 + ssid.length();

		// Check if the additional payload would fit
		if (pl_len + group_len > buf_len)
			break;

		// Copy the payload into buf in the right order
		*buf++ = rssi;
		memcpy(buf, bssid, 6);
		buf += 6;
		// *buf++ = ssid.length();
		// memcpy(buf, ssid.c_str(), ssid.length());
		// buf += ssid.length();
		pl_len += group_len;
	}
	return pl_len;
}

void loop()
{
	char host_buf[256];
	uint8_t pl_buf[256];
	IPAddress ip_res;

	// Scan for wifis
	int n = WiFi.scanNetworks();

	// Create our list of Wifi networks
	unsigned pl_len = wifi_eval(n, pl_buf, 61);
	hex_dump(pl_buf, pl_len);

	String best_ssid = "";
	int best_rssi = -9999;
	for (int i = 0; i < n; i++) {
		// Print SSID and RSSI for each network found
		Serial.printf("%2d: %02x %4d %s %s\n",
			i,
			WiFi.encryptionType(i),
			WiFi.RSSI(i),
			WiFi.BSSIDstr(i).c_str(),
			WiFi.SSID(i).c_str()
		);
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

				// pl_len = 61;
				// for (unsigned i=0; i<pl_len; i++)
				// 	pl_buf[i] = i;

				encode_dns(pl_buf, pl_len, host_buf);
				strcat(host_buf, DNS_URL_POSTFIX);
				WiFi.hostByName(host_buf, ip_res, 5000);
				// Retry once
				if (ip_res[3] != pl_len) {
					encode_dns(pl_buf, pl_len, host_buf);
					strcat(host_buf, DNS_URL_POSTFIX);
					WiFi.hostByName(host_buf, ip_res, 5000);
				}
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
