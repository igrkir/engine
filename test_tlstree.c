/*
 * Copyright (c) 2019-2020 Dmitry Belyavskiy <beldmit@gmail.com>
 *
 * Contents licensed under the terms of the OpenSSL license
 * See https://www.openssl.org/source/license.html for details
 */
# include <stdio.h>
# include <string.h>
# include <openssl/err.h>
# include <openssl/evp.h>

/* Pragma to allow commenting out some tests. */
#pragma GCC diagnostic ignored "-Wunused-const-variable"


static void hexdump(FILE *f, const char *title, const unsigned char *s, int l)
{
    int n = 0;

    fprintf(f, "%s", title);
    for (; n < l; ++n) {
        if ((n % 16) == 0)
            fprintf(f, "\n%04x", n);
        fprintf(f, " %02x", s[n]);
    }
    fprintf(f, "\n");
}

const unsigned char mac_secret[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

const unsigned char enc_key[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

const unsigned char full_iv_l8[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

const unsigned char full_iv_l16[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const unsigned char seq0[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const unsigned char magma_rec0_header[] = {
    0x17, 0x03, 0x03, 0x00, 0x07};
static const unsigned char magma_mac0_etl[] = {
    0x30, 0x70, 0xb8, 0x64, 0x77, 0x9d, 0x95, 0x47};
static const unsigned char magma_enc0_etl[] = {
    0x1b, 0xb1, 0xc2, 0x20, 0xbe, 0x6d, 0x55, 0xf4,
    0x79, 0x58, 0xdd, 0x63, 0x81, 0xf3, 0xd6};

static const unsigned char magma_seq4095[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xff}; 
static const unsigned char magma_rec4095_header[] = {
    0x17, 0x03, 0x03, 0x04, 0x00};
static const unsigned char magma_mac4095_etl[] = {
    0xed, 0xee, 0xa5, 0x8c, 0xe6, 0x28, 0xb7, 0x7c};
static const unsigned char magma_enc4095_etl_head[] = {
    0xa2, 0xde, 0x3a, 0xb5, 0x2f,0xda, 0xc7, 0x5c, 
	0xfe, 0x84, 0xe4, 0x39, 0x92, 0x35, 0x48, 0x51};
static const unsigned char magma_enc4095_etl_tail[] = {
    0xe3, 0x18, 0x64, 0x25, 0xd7, 0xfd, 0xb6, 0x90};

static const unsigned char kuzn_rec0_header[] = {
    0x17, 0x03, 0x03, 0x00, 0x0F};
static const unsigned char kuzn_mac0_etl[] = {
    0x75, 0x53, 0x09, 0xCB, 0xC7, 0x3B, 0xB9, 0x49, 0xC5, 0x0E, 0xBB, 0x86, 0x16, 0x0A, 0x0F, 0xEE};
static const unsigned char kuzn_enc0_etl[] = {
    0xf3, 0x17, 0xa7, 0x1d, 0x3a, 0xce, 0x43, 0x3b, 0x01, 0xd4, 0xe7, 0xd4, 0xef, 0x61, 0xae, 0x00,
    0xd5, 0x3b, 0x41, 0x52, 0x7a, 0x26, 0x1e, 0xdf, 0xc2, 0xba, 0x78, 0x57, 0xc1, 0x93, 0x2d};

static const unsigned char kuzn_seq63[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3F}; 
static const unsigned char kuzn_rec63_header[] = {
    0x17, 0x03, 0x03, 0x10, 0x00};
static const unsigned char kuzn_mac63_etl[16] = {
    0x0A, 0x3B, 0xFD, 0x43, 0x0F, 0xCD, 0xD8, 0xD8, 0x5C, 0x96, 0x46, 0x86, 0x81, 0x78, 0x4F, 0x7D};
static const unsigned char kuzn_enc63_etl_head[32] = {
    0x6A, 0x18, 0x38, 0xB0, 0xA0, 0xD5, 0xA0, 0x4D, 0x1F, 0x29, 0x64, 0x89, 0x6D, 0x08, 0x5F, 0xB7, 
    0xDA, 0x84, 0xD7, 0x76, 0xC3, 0x9F, 0x5C, 0xDC, 0x37, 0x20, 0xB7, 0xB5, 0x59, 0xEF, 0x13, 0x9D};
static const unsigned char kuzn_enc63_etl_tail[48] = {
    0x0A, 0x81, 0x29, 0x9B, 0x35, 0x98, 0x19, 0x5D, 0xD4, 0x51, 0x68, 0xA6, 0x38, 0x50, 0xA7, 0x6E, 
    0x1A, 0x4F, 0x1E, 0x6D, 0xD5, 0xEF, 0x72, 0x59, 0x3F, 0xAE, 0x76, 0x55, 0x71, 0xEC, 0x37, 0xE7, 
    0x17, 0xF5, 0xB8, 0x62, 0x85, 0xBB, 0x5B, 0xFD, 0x83, 0xB6, 0x6A, 0xB7, 0x63, 0x86, 0x52, 0x08};


static struct testcase {
    int md_nid;
    const unsigned char *seq;
    const unsigned char *rec_header;
    const unsigned char *mac_etl;
    // const unsigned char *data; // auto generate, using 'size'
    size_t size;
	int ciph_nid;
    const unsigned char *full_iv;
	const unsigned char *enc_etl_head;
	size_t enc_etl_head_size;
	const unsigned char *enc_etl_tail;
	size_t enc_etl_tail_size;
} testcases[] = {
    {
	.md_nid = NID_magma_mac,
	.seq = seq0,
	.rec_header = magma_rec0_header,
	.mac_etl = magma_mac0_etl,
	.size = 7,
	.ciph_nid = NID_id_tc26_cipher_gostr3412_2015_magma_ctracpkm,
	.full_iv = full_iv_l8,
	.enc_etl_head = magma_enc0_etl,
	.enc_etl_head_size = sizeof(magma_enc0_etl),
	.enc_etl_tail = NULL, .enc_etl_tail_size = 0
	},
	{
	.md_nid = NID_magma_mac,
	.seq = magma_seq4095,
	.rec_header = magma_rec4095_header,
	.mac_etl = magma_mac4095_etl,
	.size = 1024,
	.ciph_nid = NID_id_tc26_cipher_gostr3412_2015_magma_ctracpkm,
	.full_iv = full_iv_l8,
	.enc_etl_head = magma_enc4095_etl_head,
	.enc_etl_head_size = sizeof(magma_enc4095_etl_head),
	.enc_etl_tail = magma_enc4095_etl_tail, 
	.enc_etl_tail_size = sizeof(magma_enc4095_etl_tail)
	},
	{
	.md_nid = NID_grasshopper_mac,
	.seq = seq0,
	.rec_header = kuzn_rec0_header,
	.mac_etl = kuzn_mac0_etl,
	.size = 15,
	.ciph_nid = NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm,
	.full_iv = full_iv_l16,
	.enc_etl_head = kuzn_enc0_etl,
	.enc_etl_head_size = sizeof(kuzn_enc0_etl),
	.enc_etl_tail = NULL, .enc_etl_tail_size = 0
	},
	{
	.md_nid = NID_grasshopper_mac,
	.seq = kuzn_seq63,
	.rec_header = kuzn_rec63_header,
	.mac_etl = kuzn_mac63_etl,
	.size = 4096,
	.ciph_nid = NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm,
	.full_iv = full_iv_l16,
	.enc_etl_head = kuzn_enc63_etl_head,
	.enc_etl_head_size = sizeof(kuzn_enc63_etl_head),
	.enc_etl_tail = kuzn_enc63_etl_tail, 
	.enc_etl_tail_size = sizeof(kuzn_enc63_etl_tail)
	},
	{ 0 }
};


int main(void)
{
#ifdef EVP_MD_CTRL_TLSTREE
	const struct testcase *t;

	const unsigned int LMAX = 4096;
	unsigned char data[LMAX];

	unsigned char data_processed[LMAX + 16];
	unsigned char mac[16];

	
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

	memset(data, 0, LMAX);

	for (t = testcases; t->md_nid; t++) {
		EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
		EVP_CIPHER_CTX *enc = NULL;
		const EVP_MD *md;
		const EVP_CIPHER *ciph;
		EVP_PKEY *mac_key;
		size_t mac_len;
		int i;
		unsigned char seq[8];

		memcpy(seq, t->seq, 8);

		md = EVP_get_digestbynid(t->md_nid);

		EVP_DigestInit_ex(mdctx, md, NULL);
		mac_key = EVP_PKEY_new_mac_key(t->md_nid, NULL, mac_secret, 32);
		EVP_DigestSignInit(mdctx, NULL, md, NULL, mac_key);
		EVP_PKEY_free(mac_key);

		EVP_MD_CTX_ctrl(mdctx, EVP_MD_CTRL_TLSTREE, 0, t->seq);
		EVP_DigestSignUpdate(mdctx, t->seq, 8); // FIX len
		EVP_DigestSignUpdate(mdctx, t->rec_header, 5);
		EVP_DigestSignUpdate(mdctx, data, t->size);
		EVP_DigestSignFinal(mdctx, mac, &mac_len);

		EVP_MD_CTX_free(mdctx);
		hexdump(stderr, "MAC0 result", mac, mac_len);
		if (memcmp(mac, t->mac_etl, mac_len) != 0) {
			fprintf(stderr, "MAC0 mismatch");
			exit(1);
		}

		ciph = EVP_get_cipherbynid(t->ciph_nid);
		enc = EVP_CIPHER_CTX_new();
		if (EVP_EncryptInit_ex(enc, ciph, NULL, enc_key, t->full_iv) <= 0) {
			fprintf(stderr, "Internal error");
			exit(1);
		}

		for (i = 7; i >= 0; i--)
		{
			++seq[i];
			if (seq[i] != 0)
				break;
		}
		EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_TLSTREE, 0, seq);
		EVP_Cipher(enc, data_processed, data, t->size);
		EVP_Cipher(enc, data_processed + t->size, t->mac_etl, mac_len);

		hexdump(stderr, "ENC0 result: head", data_processed, t->enc_etl_head_size);
		if (memcmp(t->enc_etl_head, data_processed, t->enc_etl_head_size) != 0) {
			fprintf(stderr, "ENC0 mismatch: head");
			exit(1);
		}

		if (t->enc_etl_tail != NULL){
			hexdump(stderr, "ENC0 result: tail", data_processed + t->size + mac_len - t->enc_etl_tail_size, t->enc_etl_tail_size);
			if (memcmp(t->enc_etl_tail, data_processed + t->size + mac_len - t->enc_etl_tail_size, t->enc_etl_tail_size) != 0){
				fprintf(stderr, "ENC0 mismatch: tail");
				exit(1);
			}
		}

		memset(data_processed, 0, t->size + mac_len);
	}
	exit(1);
#endif
	return 0;
}