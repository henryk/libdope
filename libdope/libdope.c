#include <gcrypt.h>
#include <assert.h>
#include "dope.h"

#define AES_KEY_LENGTH 16
//#define LONG_TERM_KEY_STRENGTH GCRY_VERY_STRONG_RANDOM
#define LONG_TERM_KEY_STRENGTH GCRY_STRONG_RANDOM

#define DOPE_CERTIFICATION_ECDSA_CURVE "NIST P-256"
#define DOPE_ENTITY_ECDSA_CURVE "NIST P-256"

#define DOPE_SIGNATURE_HASH_TYPE_0 GCRY_MD_SHA256

#define GCRYPT_ERROR(r) fprintf(stderr, "ERROR: %s:%i: %s/%s\n", __FILE__, __LINE__, gcry_strsource(r), gcry_strerror(r))

typedef struct dope_key_flags {
	unsigned int debit:1;
	unsigned int limited_credit:1;
	unsigned int credit:1;
} __attribute__((packed)) dope_key_flags;

#define DOPE_CERTIFICATE_KEY_FLAG_DEBIT          (1<<0)
#define DOPE_CERTIFICATE_KEY_FLAG_LIMITED_CREDIT (1<<1)
#define DOPE_CERTIFICATE_KEY_FLAG_CREDIT         (1<<2)

struct dope_secret_key {
	enum dope_secret_key_type {
		DOPE_SECRET_KEY_TYPE_INVALID = 0,
		DOPE_SECRET_KEY_TYPE_MASTER,
		DOPE_SECRET_KEY_TYPE_IDENTIFICATION,
		DOPE_SECRET_KEY_TYPE_DEBIT,
		DOPE_SECRET_KEY_TYPE_LIMITED_CREDIT,
		DOPE_SECRET_KEY_TYPE_CREDIT,
	} type;
	size_t length;
	uint8_t key[AES_KEY_LENGTH];
	uint8_t version;
	struct dope_secret_key *next;
};

static const char* DOPE_SECRET_KEY_NAMES[] = {
		[DOPE_SECRET_KEY_TYPE_INVALID] = NULL,
		[DOPE_SECRET_KEY_TYPE_MASTER] = "master",
		[DOPE_SECRET_KEY_TYPE_IDENTIFICATION] = "identification",
		[DOPE_SECRET_KEY_TYPE_DEBIT] = "debit",
		[DOPE_SECRET_KEY_TYPE_LIMITED_CREDIT] = "limited_credit",
		[DOPE_SECRET_KEY_TYPE_CREDIT] = "credit",
};

struct dope_context {
	uint8_t roles_initialized;

	struct dope_secret_key *key_head;

	gcry_sexp_t certification_public_key;
	gcry_sexp_t certification_private_key;

	struct dope_identity {
		uint32_t key_identifier;
		dope_key_flags key_flags;
		gcry_sexp_t public_key;
		gcry_sexp_t private_key;
		uint8_t *certificate;
		size_t certificate_length;
	} identity;

	int open_connections;
};

struct dope_connection {
	struct dope_context *ctx;
};

static bool _init_gcrypt(void)
{
	if(gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
		return 1;
	}
	if(!gcry_check_version(NULL)) {
		return 0;
	} else {
		return 1;
	}
}

static void _clean_identity(struct dope_identity *id)
{
	if(id == NULL) {
		return;
	}
	gcry_sexp_release(id->private_key);
	gcry_sexp_release(id->public_key);
	if(id->certificate != NULL) {
		memset(id->certificate, 0, id->certificate_length);
		free(id->certificate);
	}
	memset(id, 0, sizeof(*id));
}

static void _free_context(struct dope_context *ctx)
{
	if(ctx == NULL) {
		return;
	}
	_clean_identity(&ctx->identity);
	gcry_sexp_release(ctx->certification_private_key);
	gcry_sexp_release(ctx->certification_public_key);
	memset(ctx, 0, sizeof(*ctx));
	gcry_free(ctx);
}

static bool _write_key_flags(FILE *fh, dope_key_flags key_flags)
{
	if(fprintf(fh, "{") != 1) {
		return 0;
	}

	int had_one = 0;
	if(key_flags.debit) {
		if(fprintf(fh, "debit") != 5) {
			return 0;
		}
		had_one = 1;
	}

	if(key_flags.limited_credit) {
		if(had_one) {
			if(fprintf(fh, ", ") != 2) {
				return 0;
			}
		}
		if(fprintf(fh, "limited_credit") != 14) {
			return 0;
		}
		had_one = 1;
	}

	if(key_flags.credit) {
		if(had_one) {
			if(fprintf(fh, ", ") != 2) {
				return 0;
			}
		}
		if(fprintf(fh, "credit") != 6) {
			return 0;
		}
		had_one = 1;
	}

	if(fprintf(fh, "}\n") != 2) {
		return 0;
	}

	return 1;
}

static bool _write_sexp_key(FILE *fh, const char *key_name, gcry_sexp_t key)
{
	assert(key != NULL);
	if(key == NULL) {
		return 0;
	}
	char *external = NULL;
	size_t external_size = gcry_sexp_sprint(key, GCRYSEXP_FMT_ADVANCED, NULL, 0);

	external = gcry_malloc_secure(external_size);
	assert(external != NULL);
	if(external == NULL) {
		return 0;
	}
	size_t r = gcry_sexp_sprint(key, GCRYSEXP_FMT_ADVANCED, external, external_size);
	size_t s = 0;

	assert(r+1==external_size);
	if(r+1 == external_size) {
		for(size_t i=0; i<r; i++) {
			if(external[i] == '\n' || external[i] == '\r') {
				external[i] = ' ';
			}
		}
		s = fprintf(fh, "%s = '%s'\n", key_name, external);
	}
	memset(external, 0, external_size);
	gcry_free(external);

	return s == strlen(key_name) + 4 + external_size - 1 + 2;
}

static bool _write_certificate(FILE *fh, const char *cert_name, const uint8_t *cert, size_t cert_length)
{
	if(cert_name == NULL || cert == NULL) {
		return 0;
	}

	if(fprintf(fh, "%s = \"", cert_name) != strlen(cert_name) + 4) {
		return 0;
	}
	for(size_t i=0; i<cert_length; i++) {
		if(fprintf(fh, "%02X", cert[i]) != 2) {
			return 0;
		}
	}
	if(fprintf(fh, "\"\n") != 2) {
		return 0;
	}

	return 1;
}

static bool _write_key_section(FILE *fh, const struct dope_secret_key *key)
{
	if(key == NULL) {
		return 0;
	}

	if(fprintf(fh, "key %s_%i {\n", DOPE_SECRET_KEY_NAMES[key->type], key->version) < strlen(DOPE_SECRET_KEY_NAMES[key->type]) + 9) {
		return 0;
	}

	if(fprintf(fh, "    key = \"") != 11) {
		return 0;
	}

	for(size_t i=0; i<key->length; i++) {
		if(fprintf(fh, "%02X", key->key[i]) != 2) {
			return 0;
		}
	}

	if(fprintf(fh, "\"\n}\n\n") != 5) {
		return 0;
	}

	return 1;
}

static int _write_master(const struct dope_context *ctx, const char *config)
{
	int retval = -1;
	FILE *fh = fopen(config, "w");
	if(fh == NULL) {
		goto abort;
	}

	fprintf(fh, "common {\n"); // FIXME Check return
	fprintf(fh, "    aid = 0xFF77CF\n");
	fprintf(fh, "    use_uid = yes\n");
	fprintf(fh, "    force_uid = no\n");
	fprintf(fh, "    roles = {master, debit, limited_credit, credit, certifier}\n");
	fprintf(fh, "}\n\n");

	fprintf(fh, "key certification {\n");
	if(!_write_sexp_key(fh, "    public_key", ctx->certification_public_key)) {
		goto abort;
	}
	if(!_write_sexp_key(fh, "    private_key", ctx->certification_private_key)) {
		goto abort;
	}
	fprintf(fh, "}\n\n");

	struct dope_secret_key *key = ctx->key_head;
	while(key != NULL) {
		if(!_write_key_section(fh, key)) {
			goto abort;
		}
		key = key->next;
	}

	fprintf(fh, "identity {\n");
	fprintf(fh, "    identifier = %i\n", ctx->identity.key_identifier);
	fprintf(fh, "    flags = ");
	if(!_write_key_flags(fh, ctx->identity.key_flags)) {
		goto abort;
	}
	if(!_write_sexp_key(fh, "    public_key", ctx->identity.public_key)) {
		goto abort;
	}
	if(!_write_sexp_key(fh, "    private_key", ctx->identity.private_key)) {
		goto abort;
	}
	if(!_write_certificate(fh, "    certificate", ctx->identity.certificate, ctx->identity.certificate_length)) {
		goto abort;
	}
	fprintf(fh, "}\n");


abort:
	if(fh != NULL) {
		fclose(fh);
	}
	return retval;
}

static bool _generate_ecdsa_key_pair(gcry_sexp_t *pubkey, gcry_sexp_t *privkey, const char *curve)
{
	bool retval = 0;
	gcry_sexp_t key_spec = NULL, key_pair = NULL, private_key = NULL, q = NULL, d = NULL;

	if(pubkey == NULL || privkey == NULL) {
		goto abort;
	}

	int r = gcry_sexp_build(&key_spec, NULL, "(genkey (ECDSA (curve %s)))", curve);
	if(r) {
		GCRYPT_ERROR(r);
		goto abort;
	}

	r = gcry_pk_genkey(&key_pair, key_spec);
	if(r) {
		GCRYPT_ERROR(r);
		goto abort;
	}

	private_key = gcry_sexp_find_token(key_pair, "private-key", 0);
	if(!private_key) {
		goto abort;
	}

	q = gcry_sexp_find_token(private_key, "q", 0);
	d = gcry_sexp_find_token(private_key, "d", 0);
	if(!q || !d) {
		goto abort;
	}


	r = gcry_sexp_build(pubkey, NULL, "(public-key (ecdsa (curve %s) %S ) )", curve, q);
	if(r) {
		GCRYPT_ERROR(r);
		goto abort;
	}

	r = gcry_sexp_build(privkey, NULL, "(private-key (ecdsa (curve %s) %S  %S) )", curve, q, d);
	if(r) {
		GCRYPT_ERROR(r);
		goto abort;
	}

	retval = 1;

abort:
	gcry_sexp_release(key_spec);
	gcry_sexp_release(key_pair);
	gcry_sexp_release(private_key);
	gcry_sexp_release(q);
	gcry_sexp_release(d);

	if(!retval) {
		if(pubkey != NULL) {
			gcry_sexp_release(*pubkey);
			*pubkey = NULL;
		}
		if(privkey != NULL) {
			gcry_sexp_release(*privkey);
			*privkey = NULL;
		}
	}

	return retval;
}

static bool _generate_secret_key(struct dope_context *ctx, enum dope_secret_key_type type, uint8_t version, size_t length, enum gcry_random_level random_level)
{
	if(ctx == NULL) {
		return 0;
	}

	if(length > sizeof( (*(struct dope_secret_key*)0).key ) ) {
		return 0;
	}

	struct dope_secret_key *key = gcry_calloc_secure(1, sizeof(*key));
	if(key == NULL) {
		return 0;
	}

	key->type = type;
	key->version = version;
	key->length = length;
	gcry_randomize(key->key, length, random_level);
	key->next = ctx->key_head;
	ctx->key_head = key;

	return 1;
}

static int _sign(const uint8_t *data, size_t data_length, int signature_type, gcry_sexp_t key, uint8_t **signature, size_t *signature_length)
{
	gcry_md_hd_t hash_md = NULL;
	gcry_sexp_t sig_data = NULL, sig_result = NULL, r_data = NULL, s_data = NULL;
	const char *r_buffer, *s_buffer; // Note: These are *inside* r_data and s_data, so don't need to be freed
	size_t r_buffer_length, s_buffer_length;
	int retval = -1;

	if(data == NULL || signature == NULL || signature_length == NULL || key == NULL) {
		goto abort;
	}

	if(signature_type != 0) {
		goto abort;
	}

	// FIXME: Check that the private key is ECDSA-NIST-P-256

	if(gcry_md_open(&hash_md, DOPE_SIGNATURE_HASH_TYPE_0, 0)) {
		goto abort;
	}

	gcry_md_putc(hash_md, signature_type);   // Signature type: 0, means ECDSA-NIST-P-256/SHA-256 with 32/32 split
	gcry_md_write(hash_md, data, data_length);

	int r = gcry_sexp_build(&sig_data, NULL, "(data (value %b ) )",
			gcry_md_get_algo_dlen(DOPE_SIGNATURE_HASH_TYPE_0), gcry_md_read(hash_md, DOPE_SIGNATURE_HASH_TYPE_0) );
	if(r) {
		goto abort;
	}

	r = gcry_pk_sign(&sig_result, sig_data, key);
	if(r) {
		goto abort;
	}

	r_data = gcry_sexp_find_token(sig_result, "r", 0);
	s_data = gcry_sexp_find_token(sig_result, "s", 0);
	if(r_data == NULL || s_data == NULL) {
		goto abort;
	}

	r_buffer = gcry_sexp_nth_data(r_data, 1, &r_buffer_length);
	s_buffer = gcry_sexp_nth_data(s_data, 1, &s_buffer_length);
	if(r_buffer == NULL || s_buffer == NULL) {
		goto abort;
	}

	// Signature type 0 needs 32/32 split
	if(r_buffer_length != 32 || s_buffer_length != 32) {
		goto abort;
	}

	size_t inner_signature_length = 1 + r_buffer_length + s_buffer_length; // 1 byte signature type, r, s
	*signature_length = 2 + inner_signature_length;

	*signature = malloc(*signature_length);
	if(*signature == NULL) {
		*signature_length = 0;
		goto abort;
	}

	(*signature)[0] = inner_signature_length & 0xff;
	(*signature)[1] = (inner_signature_length>>8) & 0xff;
	(*signature)[2] = signature_type;

	memcpy(*signature + 3, r_buffer, r_buffer_length);
	memcpy(*signature + 3 + r_buffer_length, s_buffer, s_buffer_length);
	retval = 0;

abort:
	gcry_md_close(hash_md);
	gcry_sexp_release(sig_data);
	gcry_sexp_release(sig_result);
	gcry_sexp_release(r_data);
	gcry_sexp_release(s_data);
	return retval;
}

static int _serialize_pubkey(gcry_sexp_t key, uint8_t **out, size_t *out_length)
{
	int retval = -1;
	gcry_sexp_t ecdsa = NULL, q = NULL;
	const char *q_buffer = NULL;
	size_t q_buffer_length;

	if(key == NULL || out == NULL || out_length == 0) {
		goto abort;
	}

	ecdsa = gcry_sexp_find_token(key, "ecdsa", 0);
	if(ecdsa == NULL) {
		goto abort;
	}

	// FIXME Check that the curve is ECDSA-NIST-P-256

	q = gcry_sexp_find_token(ecdsa, "q", 0);
	if(q == NULL) {
		goto abort;
	}

	q_buffer = gcry_sexp_nth_data(q, 1, &q_buffer_length);
	if(q_buffer == NULL) {
		goto abort;
	}

	size_t inner_length = 1 + q_buffer_length; // 1 byte pubkey type, q
	*out_length = 2 + inner_length;

	*out = malloc(*out_length);
	if(*out == NULL) {
		*out_length = 0;
		goto abort;
	}

	(*out)[0] = inner_length & 0xFF;
	(*out)[1] = (inner_length>>8) & 0xFF;
	(*out)[2] = 0; // Pubkey type 0 for ECDSA-NIST-P-256
	memcpy(*out + 3, q_buffer, q_buffer_length);
	retval = 0;

abort:
	gcry_sexp_release(ecdsa);
	gcry_sexp_release(q);
	return retval;
}

static int _sign_identity(struct dope_context *ctx, struct dope_identity *id)
{
	if(ctx == NULL || id == NULL) {
		return -1;
	}

	if(id->certificate != NULL) {
		memset(id->certificate, 0, id->certificate_length);
		free(id->certificate);
		id->certificate = NULL;
	}

	int retval = -1;
	uint8_t *cert = NULL, *pubkey = NULL, *cert_data = NULL, *signature = NULL;
	size_t cert_length = 0, pubkey_length = 0, cert_data_length = 0, signature_length = 0;

	if(_serialize_pubkey(id->public_key, &pubkey, &pubkey_length) < 0) {
		goto abort;
	}

	cert_data_length = 6 + pubkey_length; // 6 bytes fixed data
	cert_data = malloc(cert_data_length);
	if(cert_data == NULL) {
		goto abort;
	}

	uint8_t flags = 0;
	if(id->key_flags.debit) {
		flags |= DOPE_CERTIFICATE_KEY_FLAG_DEBIT;
	}
	if(id->key_flags.limited_credit) {
		flags |= DOPE_CERTIFICATE_KEY_FLAG_LIMITED_CREDIT;
	}
	if(id->key_flags.credit) {
		flags |= DOPE_CERTIFICATE_KEY_FLAG_CREDIT;
	}

	cert_data[0] = 0x00; // certificate format
	cert_data[1] = (id->key_identifier >>  0) & 0xff; // key identifier, LSByte first
	cert_data[2] = (id->key_identifier >>  8) & 0xff;
	cert_data[3] = (id->key_identifier >> 16) & 0xff;
	cert_data[4] = (id->key_identifier >> 24) & 0xff;
	cert_data[5] = flags; // key flags

	memcpy(cert_data + 6, pubkey, pubkey_length);

	if(_sign(cert_data, cert_data_length, 0, ctx->certification_private_key, &signature, &signature_length) < 0){
		goto abort;
	}

	cert_length = cert_data_length + signature_length;
	cert = malloc(cert_length);
	if(cert == NULL) {
		goto abort;
	}

	memcpy(cert, cert_data, cert_data_length);
	memcpy(cert + cert_data_length, signature, signature_length);

	id->certificate = cert;
	id->certificate_length = cert_length;
	retval = 0;

abort:
	if(cert != NULL && retval < 0) {
		free(cert);
	}
	if(pubkey != NULL) {
		free(pubkey);
	}
	if(cert_data != NULL) {
		free(cert_data);
	}
	if(signature != NULL) {
		free(signature);
	}

	return retval;
}

int dope_create_master(const char *config)
{
	if(!_init_gcrypt()) {
		return -1;
	}

	if(config == NULL) {
		return -1;
	}

	int retval = -1;
	struct dope_context *ctx = NULL;

	ctx = gcry_calloc_secure(1, sizeof(*ctx));
	if(ctx == NULL) {
		goto abort;
	}

	if(! _generate_ecdsa_key_pair(&ctx->certification_public_key, &ctx->certification_private_key, DOPE_CERTIFICATION_ECDSA_CURVE) ) {
		goto abort;
	}

	if(! _generate_ecdsa_key_pair(&ctx->identity.public_key, &ctx->identity.private_key, DOPE_ENTITY_ECDSA_CURVE) ) {
		goto abort;
	}

	ctx->identity.key_identifier = 1;
	ctx->identity.key_flags = (dope_key_flags){.credit = 1, .limited_credit = 1, .debit = 1};
	if(_sign_identity(ctx, &ctx->identity) < 0) {
		goto abort;
	}

	if(!_generate_secret_key(ctx, DOPE_SECRET_KEY_TYPE_CREDIT, 0, AES_KEY_LENGTH, LONG_TERM_KEY_STRENGTH)) {
		goto abort;
	}

	if(!_generate_secret_key(ctx, DOPE_SECRET_KEY_TYPE_LIMITED_CREDIT, 0, AES_KEY_LENGTH, LONG_TERM_KEY_STRENGTH)) {
		goto abort;
	}

	if(!_generate_secret_key(ctx, DOPE_SECRET_KEY_TYPE_DEBIT, 0, AES_KEY_LENGTH, LONG_TERM_KEY_STRENGTH)) {
		goto abort;
	}

	if(!_generate_secret_key(ctx, DOPE_SECRET_KEY_TYPE_IDENTIFICATION, 0, AES_KEY_LENGTH, LONG_TERM_KEY_STRENGTH)) {
		goto abort;
	}

	if(!_generate_secret_key(ctx, DOPE_SECRET_KEY_TYPE_MASTER, 0, AES_KEY_LENGTH, LONG_TERM_KEY_STRENGTH)) {
		goto abort;
	}


	retval = _write_master(ctx, config);

abort:
	_free_context(ctx);

	return retval;
}
