#ifndef DNS_SNEAKER_H_
#define DNS_SNEAKER_H_
// Sneak some data through public hot-spots, disguised as DNS requests.
// This implements a small protocol layer for variable sized payloads
// with CRC16 and symetric encryption.
// Up to 239 character DNS request yields a 149 byte payload

// s_key_16 is the 16 byte secret key
// s_iv_16 is the 16 bytes initialization vector,
// should be a unpredictable random number and only used __once__!!
void encode_dns_init(const uint8_t *s_key_16, const uint8_t *s_iv_16, const char* cod_tbl);

// encodes dataBuffer into a DNS query string
// `buf_out` must be a user provided string buffer
extern void encode_dns(uint8_t *buf_in, unsigned len, char *buf_out);


#endif /* DNS_SNEAKER_H_ */
