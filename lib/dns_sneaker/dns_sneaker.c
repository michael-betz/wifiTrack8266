#include <string.h>
#include "dns_sneaker.h"
#include "aes.h"

/**
 * This convert a 5 bits value into a base32 character.
 * Only the 5 least significant bits are used.
 */
static uint8_t encode_char(uint8_t c){
	static uint8_t base32[] = CODING_TABLE;
	return base32[c & 0x1F];  // 0001 1111
}

// encodes 5 bits to 1 byte symbol. Returns pointer to next free element in symbolOutBuffer
static uint8_t *base32Encode(uint8_t *plainBuffer, uint32_t len, uint8_t *symbolOutBuffer){
	uint8_t tmp;
	uint16_t remainder = 0;
	uint8_t remainderCnt = 0;
	uint32_t symbolCount = 0;
	// tempWord holds 64 plain bits --> encodes to 12 whole symbols, remainder 4 bits
	while( 1 ){
		if( remainderCnt >= 5 ){		// Try to consume 5 bits from the remainder
			*symbolOutBuffer++ = encode_char( remainder );
			symbolCount++;
			remainderCnt -= 5;
			remainder >>= 5;
		} else {						// Otherwise extend the remainder with 8 fresh bits
			if( len > 0 ){
				tmp = *plainBuffer++;
				remainder |= tmp << remainderCnt;
				remainderCnt += 8;
				len--;
			} else {					// If all plaintext has been encoded, send out the remainder and exit
				if( remainderCnt > 0 ){
					*symbolOutBuffer++ = encode_char( remainder );
					symbolCount++;
				}
				break;
			}
		}
	}
	return symbolOutBuffer;
}

static uint16_t gRunningCrc = 0xFFFF;          // Global variable to keep CRC state
#define resetRunnningCRC() {gRunningCrc=0xFFFF;}

// Modbus-RTU compatible CRC calculation. This one operates on byte streams and keeps state.
static void runningCRC( uint8_t inputByte ) {
    gRunningCrc ^= inputByte;
    for( uint8_t b=0; b<=7; b++ ){     // For each bit in the byte
        gRunningCrc = (gRunningCrc & 1) ? ((gRunningCrc >> 1) ^ 0xA001) : (gRunningCrc >> 1);
    }
}

// AES encrypt a 16 byte block in place
static void encryptBlock( uint8_t *byteBlock ){
	static struct AES_ctx ctx;
	static uint8_t isInit = 0;
	if(!isInit) {
		static const uint8_t s_key[] = SECRET_KEY_128;
		AES_init_ctx(&ctx, s_key);
		isInit = 1;
	}
	AES_ECB_encrypt(&ctx, byteBlock);
}

// encodes dataBuffer into a DNS query string
// `dnsRequestBuffer` must be a user provided string buffer of size DNS_REQUEST_BUFFER_SIZE()
void dnsEncode(uint8_t *dataBuffer, uint8_t payloadLength, uint8_t *dnsRequestBuffer){
	uint8_t encryptionBuffer[AES_BLOCK_SIZE];
	uint8_t *strPtr = dnsRequestBuffer, temp;

	//-----------------------------------------------------------------
	// Iterate through buffer in 16 byte chuncks and AES encrypt them
	// Set [payloadLength, CRCH, CRCL] as the last 3 bytes of the last
	// AES buffer (before encryption)
	//-----------------------------------------------------------------
	uint8_t chunkNumber = 0;
	uint8_t tempDataLength = payloadLength+3;	//Make sure loop processes payload + 3 additional housekeeping bytes
	resetRunnningCRC();
	while( tempDataLength > 0 ){
		for( uint8_t i=0; i<AES_BLOCK_SIZE; i++ ){
			if( tempDataLength > 3 ){			//Encode a payload byte (and keep track of CRC)
				temp = *dataBuffer++;
				runningCRC( temp );
				tempDataLength--;
			} else if ( tempDataLength==3 && i==(AES_BLOCK_SIZE-3) ) {	//Encode the payload length
				temp = payloadLength;									//Will end up as third last byte
				tempDataLength--;
			} else if ( tempDataLength==2 && i==(AES_BLOCK_SIZE-2) ) {	//Encode the upper CRC byte
				temp = gRunningCrc>>8;									//Will end up as second last byte
				tempDataLength--;
			} else if ( tempDataLength==1 && i==(AES_BLOCK_SIZE-1) ) {	//Encode the lower CRC byte
				temp = gRunningCrc;										//Will end up as last byte
				tempDataLength--;
			} else {							// Nothing to encode. Pad this part of the AES block with zeros
				temp = 0;
			}
			encryptionBuffer[i] = temp;
		}
		encryptBlock(encryptionBuffer);
		// We need to encode 16 byte but base32_encode operates on 5 byte blocks
		// encoding 16 bytes should result in 26 symbols
		strPtr = base32Encode( encryptionBuffer, AES_BLOCK_SIZE, strPtr );
		*strPtr++ = '.';
		chunkNumber++;
	}
	strcpy((char*)strPtr, DNS_URL_POSTFIX);
}
