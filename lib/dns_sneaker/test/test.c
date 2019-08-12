// For testing on linux
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "dns_sneaker.h"

int main(int argc, char const *argv[])
{
	unsigned isError = 0;
	// AES secret key
	static const uint8_t sk[16] = "Sixteen byte key";
	// AES initial vector
	static const uint8_t iv[16] = "0123456789ABCDEF";
	// Base32 alphabet lookup table
	static const char g_cod_tbl[32] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	// Plain text (=payload)
	static uint8_t p_txt[] = "12345abcABC";
	// Cypher text (=domain name query)
	char c_txt[256];
	// expected results (from dns_sneak_dev.ipynb)
	const char *c_txt_exp[] = {
		"RAAWNR7U5YQ66TI5L7OXOTWU7B",
		"ODVZONSXXZGIRUPRYGWF2AYXUE",
		"4HV35HGN44EEI5Y7E54HYS764C",
		"CPOB4QD4YTE4HZ2PJT3UWJI63C"
	};

	encode_dns_init(sk, iv, g_cod_tbl);

	for (unsigned i=0; i<4; i++) {
		encode_dns(p_txt, strlen((char*)p_txt), c_txt);
		printf("%s\n%s expected\n\n", c_txt, c_txt_exp[i]);
		isError |= strcmp(c_txt, c_txt_exp[i]);
	}

	printf(isError ? "FAIL\n" : "PASS\n");
	return isError;
}
