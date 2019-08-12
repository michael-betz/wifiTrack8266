#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "dns_sneaker.h"
#define ECB 0
#define CTR 0
#include "aes.h"

// payload is padded to integer multiple of AES_BLOCK_SIZE before AES encryption
#define AES_BLOCK_SIZE 16

// maximum length [chars] of a DNS sub-domain
#define LBL_LEN 63

static const char *g_cod_tbl;

// Print a pretty hex-dump for debugging
// void sn_hex_dump(uint8_t *buffer, unsigned len){
// 	for( uint16_t i=0; i<len; i++ ){
// 		if( (len>16) && ((i%16)==0) ){
// 			printf("\n    %04x: ",i);
// 		}
// 		printf("%02x ",*buffer++);
// 	}
// 	printf("\n");
// }
#define sn_hex_dump(a, b)

static uint16_t g_crc = 0xFFFF;          // Global variable to keep CRC state
static void reset_crc() { g_crc = 0xFFFF; }

// Modbus-RTU compatible CRC calculation. This one operates on byte streams and keeps state.
static void run_crc(uint8_t inputByte) {
	g_crc ^= inputByte;
	for( uint8_t b=0; b<=7; b++ ){     // For each bit in the byte
		g_crc = (g_crc & 1) ? ((g_crc >> 1) ^ 0xA001) : (g_crc >> 1);
	}
}

// This convert a 5 bits value into a base32 character, only the 5 least significant bits are used.
static char enc_char(uint8_t c) {
	return g_cod_tbl[c & 0x1F];  // 0001 1111
}

// encodes 5 bits to 1 byte symbol. Returns pointer to next free element in symbolOutBuffer
static char *enc_b32(uint8_t *plainBuffer, uint32_t len, char *symbolOutBuffer) {
	uint8_t tmp;
	uint16_t remainder = 0;
	uint8_t remainderCnt = 0;
	uint32_t charCount = 0;
	while(1) {
		// Try to consume 5 bits from the remainder
		if(remainderCnt >= 5) {
			*symbolOutBuffer++ = enc_char(remainder);
			// Add a '.' every 63 characters
			if ((++charCount % LBL_LEN) == 0) {
				*symbolOutBuffer++ = '.';
			}
			remainderCnt -= 5;
			remainder >>= 5;
		// Otherwise add 8 fresh bits to the remainder
		} else {
			if (len > 0) {
				tmp = *plainBuffer++;
				remainder |= tmp << remainderCnt;
				remainderCnt += 8;
				len--;
			// If all plaintext has been encoded, send out the remainder and exit
			} else {
				if(remainderCnt > 0) {
					*symbolOutBuffer++ = enc_char(remainder);
				}
				break;
			}
		}
	}
	*symbolOutBuffer = 0;
	return symbolOutBuffer;
}

static struct AES_ctx g_ctx;

// s_key_16 is the 16 byte secret key
// s_iv_16 is the 16 bytes initialization vector,
// should be a unpredictable random number and only used __once__!!
// cod_tbl is a 32 byte coding table with the alphabet used for DNS
void encode_dns_init(const uint8_t *s_key_16, const uint8_t *s_iv_16, const char* cod_tbl)
{
	g_cod_tbl = cod_tbl;
	AES_init_ctx_iv(&g_ctx, s_key_16, s_iv_16);
}

// encodes dataBuffer into a DNS query string
void encode_dns(uint8_t *buf_in, unsigned len, char *buf_out)
{
	uint8_t temp_buf[256], *p=buf_in, *q=temp_buf;
	unsigned i;

	sn_hex_dump(buf_in, len);

	// Copy into temp_buf and add CRC16 fields
	reset_crc();
	for(i=0; i<len; i++) {
		run_crc(*p);
		*q++ = *p++;
	}
	*q++ = g_crc >> 8;
	*q++ = g_crc;
	len += 2;

	// Pad pl to mod. AES_BLOCK_SIZE bytes
	unsigned n_pad = AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE);
	for(i=0; i<n_pad; i++)
		*q++ = n_pad;
	len += n_pad;
	sn_hex_dump(temp_buf, len);

	// Encrypt payload buffer
	AES_CBC_encrypt_buffer(&g_ctx, temp_buf, len);
	sn_hex_dump(temp_buf, len);

	// encode b32 with added '.' in the right places
	enc_b32(temp_buf, len, buf_out);
}
