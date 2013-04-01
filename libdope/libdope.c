#include <gcrypt.h>
#include <assert.h>
#include <confuse.h>
#include "dope.h"

#define AES_KEY_LENGTH 16
#define LONG_TERM_KEY_STRENGTH GCRY_VERY_STRONG_RANDOM
//#define LONG_TERM_KEY_STRENGTH GCRY_STRONG_RANDOM

#define DOPE_CERTIFICATION_ECDSA_CURVE "NIST P-256"
#define DOPE_ENTITY_ECDSA_CURVE "NIST P-256"

#define DOPE_SIGNATURE_HASH_TYPE_0 GCRY_MD_SHA256

#define GCRYPT_ERROR(r) fprintf(stderr, "ERROR: %s:%i: %s/%s\n", __FILE__, __LINE__, gcry_strsource(r), gcry_strerror(r))

#define DOPE_CERTIFICATE_KEY_FLAG_DEBIT          (1<<0)
#define DOPE_CERTIFICATE_KEY_FLAG_LIMITED_CREDIT (1<<1)
#define DOPE_CERTIFICATE_KEY_FLAG_CREDIT         (1<<2)
#define DOPE_CERTIFICATE_VALID_KEY_FLAGS (DOPE_CERTIFICATE_KEY_FLAG_DEBIT | DOPE_CERTIFICATE_KEY_FLAG_LIMITED_CREDIT | DOPE_CERTIFICATE_KEY_FLAG_CREDIT)

#define DOPE_SECRET_KEY_VERSION_FIRST -1  /* Find first secret key of given type, ignore version */

#define DOPE_DEFAULT_AID 0xFF77CF

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

static const struct {
	enum dope_role role;
	const char *name;
	enum dope_secret_key_type keys[5];
	bool need_certification_private;
} DOPE_ROLE_KEY_REQUIREMENTS[] = {
		{DOPE_ROLE_MASTER, "master", {DOPE_SECRET_KEY_TYPE_MASTER, DOPE_SECRET_KEY_TYPE_IDENTIFICATION, DOPE_SECRET_KEY_TYPE_DEBIT, DOPE_SECRET_KEY_TYPE_LIMITED_CREDIT, DOPE_SECRET_KEY_TYPE_CREDIT}, 0},
		{DOPE_ROLE_CERTIFIER, "certifier", {DOPE_SECRET_KEY_TYPE_INVALID}, 1},
		{DOPE_ROLE_DEBIT, "debit", {DOPE_SECRET_KEY_TYPE_IDENTIFICATION, DOPE_SECRET_KEY_TYPE_DEBIT}, 0},
		{DOPE_ROLE_LIMITED_CREDIT, "limited_credit", {DOPE_SECRET_KEY_TYPE_IDENTIFICATION, DOPE_SECRET_KEY_TYPE_DEBIT, DOPE_SECRET_KEY_TYPE_LIMITED_CREDIT}, 0},
		{DOPE_ROLE_CREDIT, "credit", {DOPE_SECRET_KEY_TYPE_IDENTIFICATION, DOPE_SECRET_KEY_TYPE_DEBIT, DOPE_SECRET_KEY_TYPE_CREDIT}, 0},
};

static const struct {
	uint8_t flag;
	const char *name;
} DOPE_KEY_FLAG_NAMES[] = {
		{DOPE_CERTIFICATE_KEY_FLAG_DEBIT, "debit"},
		{DOPE_CERTIFICATE_KEY_FLAG_LIMITED_CREDIT, "limited_credit"},
		{DOPE_CERTIFICATE_KEY_FLAG_CREDIT, "credit"},
};

struct dope_context {
	uint32_t aid;
	bool use_uid;
	bool force_uid;
	uint8_t roles_initialized;

	struct dope_secret_key *key_head;

	gcry_sexp_t certification_public_key;
	gcry_sexp_t certification_private_key;

	struct dope_identity {
		uint32_t key_identifier;
		uint8_t key_flags;
		gcry_sexp_t public_key;
		gcry_sexp_t private_key;
		uint8_t *certificate;
		size_t certificate_length;
	} identity;

	int open_connections;

	dope_log_cb_t log_callback;
	void *log_callback_p;
};

#define DOPE_APPLICATION_FLAG_LIMITED_CREDIT_ENABLED (1<<0)
#define DOPE_APPLICATION_FLAG_KEY_DERIVATION_INSTANCE_FOR_DEBIT (1<<1)
#define DOPE_APPLICATION_FLAG_KEY_DERIVATION_INSTANCE_FOR_CREDIT (1<<2)
#define DOPE_APPLICATION_FLAG_KEY_DERIVATION_UID (1<<3)
#define DOPE_APPLICATION_FLAG_KEY_DERIVATION_RESERVED_MASK (3<<4)
#define DOPE_APPLICATION_FLAG_SIGNATURE_UID (1<<6)
#define DOPE_APPLICATION_FLAG_CERTIFCATE_ON_CARD (1<<7)
#define DOPE_APPLICATION_FLAG_SIGNATURE_FORMAT_MASK (0xf<<8)
#define DOPE_APPLICATION_FLAG_SIGNATURE_FORMAT_0 (0<<8)

#define INSTANCE_IDENTIFIER_MAX_LENGTH 16
#define SIGNATURE_FILE_MAX_LENGTH 256 /* Is really 252, but I'm a little fuzzy on the length of the public key */
#define IDENTIFICATION_FILE_MAX_LENGTH 20

struct dope_connection {
	struct dope_context *ctx;
	struct dope_application {
		uint8_t version;
		uint8_t instance_identifier[INSTANCE_IDENTIFIER_MAX_LENGTH];
		size_t instance_identifier_length;
		uint16_t flags;

		int32_t transaction_counter;

		int32_t cash_value;
		int32_t cash_value_max;

		size_t identification_file_length;
		uint8_t identification_file[IDENTIFICATION_FILE_MAX_LENGTH];

		size_t signature_file_length;
		uint8_t signature_file[SIGNATURE_FILE_MAX_LENGTH];
	} app;
};

static cfg_opt_t common_opts[] = {
		CFG_INT("aid", DOPE_DEFAULT_AID, CFGF_NONE),
		CFG_BOOL("use_uid", 1, CFGF_NONE),
		CFG_BOOL("force_uid", 0, CFGF_NONE),
		CFG_STR_LIST("roles", "", CFGF_NODEFAULT),
		CFG_END(),
};

static cfg_opt_t key_opts[] = {
		CFG_STR("key", "", CFGF_NODEFAULT),
		CFG_STR("public_key", "", CFGF_NODEFAULT),
		CFG_STR("private_key", "", CFGF_NODEFAULT),
		CFG_END(),
};

static cfg_opt_t identity_opts[] = {
		CFG_INT("identifier", -1, CFGF_NONE),
		CFG_STR_LIST("flags", "", CFGF_NODEFAULT),
		CFG_STR("public_key", NULL, CFGF_NONE),
		CFG_STR("private_key", NULL, CFGF_NONE),
		CFG_STR("certificate", NULL, CFGF_NONE),
		CFG_END(),
};

static cfg_opt_t dope_opts[] = {
		CFG_SEC("common", common_opts, CFGF_NODEFAULT),
		CFG_SEC("key", key_opts, CFGF_MULTI | CFGF_TITLE | CFGF_NO_TITLE_DUPES),
		CFG_SEC("identity", identity_opts, CFGF_NODEFAULT),
		CFG_END(),
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

static bool _write_key_flags(FILE *fh, uint8_t key_flags)
{
	if(fprintf(fh, "{") != 1) {
		return 0;
	}

	int had_one = 0;
	for(size_t i = 0; i<sizeof(DOPE_KEY_FLAG_NAMES)/sizeof(DOPE_KEY_FLAG_NAMES[0]); i++) {
		if(key_flags & DOPE_KEY_FLAG_NAMES[i].flag) {
			if(had_one) {
				if(fprintf(fh, ", ") != 2) {
					return 0;
				}
			}

			if(fprintf(fh, "%s", DOPE_KEY_FLAG_NAMES[i].name) != strlen(DOPE_KEY_FLAG_NAMES[i].name)) {
				return 0;
			}

			had_one = 1;
		}
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

static bool _write_roles(FILE *fh, uint8_t roles)
{
	int had_one = 0;
	for(size_t i=0; i<sizeof(DOPE_ROLE_KEY_REQUIREMENTS)/sizeof(DOPE_ROLE_KEY_REQUIREMENTS[0]); i++) {
		if(roles & (1<<DOPE_ROLE_KEY_REQUIREMENTS[i].role)) {
			if(had_one) {
				if(fprintf(fh, ", ") != 2) {
					return 0;
				}
			}
			if(fprintf(fh, "%s", DOPE_ROLE_KEY_REQUIREMENTS[i].name) != strlen(DOPE_ROLE_KEY_REQUIREMENTS[i].name)) {
				return 0;
			}

			had_one = 1;
		}
	}
	return 1;
}

static int _write_config(const struct dope_context *ctx, const char *config)
{
	int retval = -1;
	FILE *fh = fopen(config, "w");
	if(fh == NULL) {
		goto abort;
	}

	fprintf(fh, "common {\n"); // FIXME Check return
	fprintf(fh, "    aid = 0x%06X\n", ctx->aid);
	fprintf(fh, "    use_uid = %s\n", ctx->use_uid ? "yes" : "no");
	fprintf(fh, "    force_uid = %s\n", ctx->force_uid ? "yes" : "no");
	fprintf(fh, "    roles = {");
	if(!_write_roles(fh, ctx->roles_initialized)) {
		goto abort;
	}
	fprintf(fh, "}\n");
	fprintf(fh, "}\n\n");

	fprintf(fh, "key certification {\n");
	if(!_write_sexp_key(fh, "    public_key", ctx->certification_public_key)) {
		goto abort;
	}
	if(ctx->certification_private_key != NULL) {
		if(!_write_sexp_key(fh, "    private_key", ctx->certification_private_key)) {
			goto abort;
		}
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

static int _verify(const uint8_t *data, size_t data_length, gcry_sexp_t key, const uint8_t *signature, size_t signature_length)
{
	gcry_md_hd_t hash_md = NULL;
	const uint8_t *r_buffer, *s_buffer; // Note: These are *inside* signature, so don't need to be freed
	size_t r_buffer_length = 0, s_buffer_length = 0;
	gcry_sexp_t sig_data = NULL, sig_value = NULL;
	int retval = -1;

	if(data == NULL || signature == NULL || key == NULL) {
		goto abort;
	}

	// Signature needs to be at least 3 bytes long: length_lo, length_hi, type
	if(signature_length < 3) {
		goto abort;
	}

	size_t inner_signature_length = signature[1];
	inner_signature_length <<= 8;
	inner_signature_length |= signature[0];

	if(inner_signature_length + 2 != signature_length) {
		goto abort;
	}

	int signature_type = signature[2];
	if(signature_type != 0) {
		// We can only handle type 0 signatures
		goto abort;
	}

	// Type 0 means ECDSA-NIST-P-256/SHA-256 with 32/32 split
	// FIXME Check that the public key is ECDSA-NIST-P-256

	r_buffer_length = 32;
	s_buffer_length = 32;

	if(inner_signature_length != 1 + r_buffer_length + s_buffer_length) {
		goto abort;
	}

	r_buffer = signature + 3;
	s_buffer = signature + 3 + r_buffer_length;


	if(gcry_md_open(&hash_md, DOPE_SIGNATURE_HASH_TYPE_0, 0)) {
		goto abort;
	}

	gcry_md_putc(hash_md, signature_type);
	gcry_md_write(hash_md, data, data_length);

	int r = gcry_sexp_build(&sig_data, NULL, "(data (value %b ) )",
			gcry_md_get_algo_dlen(DOPE_SIGNATURE_HASH_TYPE_0), gcry_md_read(hash_md, DOPE_SIGNATURE_HASH_TYPE_0) );
	if(r) {
		goto abort;
	}

	r = gcry_sexp_build(&sig_value, NULL, "(sig-val (ecdsa (r %b) (s %b) ) )", r_buffer_length, r_buffer, s_buffer_length, s_buffer);
	if(r) {
		goto abort;
	}

	r = gcry_pk_verify(sig_value, sig_data, key);
	if(r) {
		goto abort;
	}

	retval = 0;

abort:
	gcry_md_close(hash_md);
	gcry_sexp_release(sig_data);
	gcry_sexp_release(sig_value);
	return retval;
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

static int _canon_cert_data(const struct dope_identity *id, uint8_t **cert_data, size_t *cert_data_length)
{
	if(id == NULL || cert_data == NULL || cert_data_length == 0) {
		return -1;
	}

	int retval = -1;
	uint8_t *pubkey = NULL;
	size_t pubkey_length = 0;

	if(_serialize_pubkey(id->public_key, &pubkey, &pubkey_length) < 0) {
		goto abort;
	}

	*cert_data_length = 6 + pubkey_length; // 6 bytes fixed data
	*cert_data = malloc(*cert_data_length);
	if(*cert_data == NULL) {
		goto abort;
	}

	uint8_t flags = 0;
	flags = id->key_flags & DOPE_CERTIFICATE_VALID_KEY_FLAGS;

	(*cert_data)[0] = 0x00; // certificate format
	(*cert_data)[1] = (id->key_identifier >>  0) & 0xff; // key identifier, LSByte first
	(*cert_data)[2] = (id->key_identifier >>  8) & 0xff;
	(*cert_data)[3] = (id->key_identifier >> 16) & 0xff;
	(*cert_data)[4] = (id->key_identifier >> 24) & 0xff;
	(*cert_data)[5] = flags; // key flags

	memcpy((*cert_data) + 6, pubkey, pubkey_length);
	retval = 0;

abort:
	if(retval < 0) {
		if(*cert_data != NULL) {
			free(*cert_data);
		}
		*cert_data = NULL;
		*cert_data_length = 0;
	}
	if(pubkey != NULL) {
		free(pubkey);
	}
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
	uint8_t *cert = NULL, *cert_data = NULL, *signature = NULL;
	size_t cert_length = 0, cert_data_length = 0, signature_length = 0;

	if(_canon_cert_data(id, &cert_data, &cert_data_length) < 0) {
		goto abort;
	}

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
	if(cert_data != NULL) {
		free(cert_data);
	}
	if(signature != NULL) {
		free(signature);
	}

	return retval;
}

static int _verify_identity(struct dope_context *ctx, struct dope_identity *id)
{
	if(ctx == NULL || id == NULL || id->certificate == NULL) {
		return -1;
	}

	int retval = -1;
	uint8_t *cert_data = NULL;
	size_t cert_data_length = 0;

	if(_canon_cert_data(id, &cert_data, &cert_data_length) < 0) {
		goto abort;
	}

	if(id->certificate_length < cert_data_length) {
		goto abort;
	}

	if(memcmp(id->certificate, cert_data, cert_data_length) != 0) {
		goto abort;
	}

	if(_verify(cert_data, cert_data_length,
			ctx->certification_public_key,
			id->certificate + cert_data_length, id->certificate_length - cert_data_length) < 0) {
		goto abort;
	}

	retval = 0;

abort:
	if(cert_data != NULL) {
		free(cert_data);
	}
	return retval;
}

static int _parse_hex(const char *in, uint8_t **out, size_t *out_length, int secure)
{
	if(in == NULL || out == NULL || out_length == NULL) {
		return -1;
	}

	size_t inlen = strlen(in);
	if(inlen % 2 != 0) {
		return -1;
	}

	int retval = -1;
	size_t buf_length = inlen/2;
	uint8_t *buf = NULL;
	if(secure) {
		buf = gcry_calloc_secure(1, buf_length);
	} else {
		buf = calloc(1, buf_length);
	}

	if(buf == NULL) {
		goto abort;
	}

	size_t pos = 0;
	for(size_t i = 0; i<inlen; i++) {
		uint8_t n;
		if(in[i] >= '0' && in[i] <= '9') {
			n = in[i] - '0';
		} else if(in[i] >= 'a' && in[i] <= 'f') {
			n = in[i] - 'a' + 10;
		} else if(in[i] >= 'A' && in[i] <= 'F') {
			n = in[i] - 'A' + 10;
		} else {
			goto abort;
		}

		if(i % 2 == 0) {
			buf[pos] = n<<4;
		} else {
			buf[pos] |= n;
			pos++;
		}
	}

	*out = buf;
	*out_length = buf_length;
	retval = 0;

abort:
	if(retval < 0) {
		if(buf != NULL) {
			memset(buf, 0, buf_length);
			if(secure) {
				gcry_free(buf);
			} else {
				free(buf);
			}
		}
	}
	return retval;
}

static int _parse_secret_key(struct dope_context *ctx, enum dope_secret_key_type type, uint8_t version, const char *value)
{
	if(ctx == NULL || value == NULL) {
		return -1;
	}

	uint8_t *buf = NULL;
	size_t buf_length = 0;
	struct dope_secret_key *key = NULL;

	int retval = -1;

	if(_parse_hex(value, &buf, &buf_length, 1) < 0) {
		goto abort;
	}

	if(buf_length > sizeof(key->key)) {
		goto abort;
	}

	key = gcry_calloc_secure(1, sizeof(*key));
	if(key == NULL) {
		goto abort;
	}

	key->length = buf_length;
	memcpy(key->key, buf, buf_length);
	key->type = type;
	key->version = version;
	key->next = ctx->key_head;
	ctx->key_head = key;
	retval = 0;

abort:
	if(buf != NULL) {
		memset(buf, 0, buf_length);
		gcry_free(buf);
	}
	if(retval < 0) {
		if(key != NULL) {
			memset(key, 0, sizeof(*key));
			gcry_free(key);
		}
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
	ctx->identity.key_flags = DOPE_CERTIFICATE_KEY_FLAG_DEBIT | DOPE_CERTIFICATE_KEY_FLAG_LIMITED_CREDIT | DOPE_CERTIFICATE_KEY_FLAG_CREDIT;
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

	ctx->aid = DOPE_DEFAULT_AID;
	ctx->use_uid = 1;
	ctx->force_uid = 0;
	ctx->roles_initialized = (1<<DOPE_ROLE_CERTIFIER) | (1<<DOPE_ROLE_CREDIT) | (1<<DOPE_ROLE_DEBIT) | (1<<DOPE_ROLE_LIMITED_CREDIT) | (1<<DOPE_ROLE_MASTER);


	retval = _write_config(ctx, config);

abort:
	_free_context(ctx);

	return retval;
}

static struct dope_secret_key *_find_secret_key(struct dope_context *ctx, enum dope_secret_key_type key_type, int key_version)
{
	if(ctx == NULL) {
		return NULL;
	}

	if(key_version == DOPE_SECRET_KEY_VERSION_FIRST) {
		// OK
	} else if(key_version >= 0 && key_version <= 255) {
		// OK
	} else {
		// key_version out of bounds
		return NULL;
	}

	struct dope_secret_key *k = ctx->key_head;
	while(k != NULL) {
		if(k->type == key_type) {
			if(key_version == DOPE_SECRET_KEY_VERSION_FIRST) {
				return k;
			} else if(key_version == key_version) {
				return k;
			}
		}
		k = k->next;
	}

	return NULL;
}

static int _copy_secret_key(struct dope_context *target, struct dope_context *source, enum dope_secret_key_type key_type)
{
	if(target == NULL || source == NULL) {
		return -1;
	}

	struct dope_secret_key *src = _find_secret_key(source, key_type, DOPE_SECRET_KEY_VERSION_FIRST);
	if(src == NULL) {
		return -1;
	}

	struct dope_secret_key *tgt = gcry_calloc_secure(1, sizeof(*tgt));
	if(tgt == NULL) {
		return -1;
	}

	memcpy(tgt, src, sizeof(*tgt));
	tgt->next = target->key_head;
	target->key_head = tgt;

	return 0;
}

static struct dope_context *_copy_context_base(dope_context_t ctx, uint8_t roles)
{
	if(ctx == NULL) {
		return NULL;
	}

	bool error = 1;
	struct dope_context *n = NULL;

	n = gcry_calloc_secure(1, sizeof(*n));
	if(n == NULL) {
		goto abort;
	}

	if(! _generate_ecdsa_key_pair(&n->identity.public_key, &n->identity.private_key, DOPE_ENTITY_ECDSA_CURVE) ) {
		goto abort;
	}

	if(gcry_sexp_build(&n->certification_public_key, NULL, "%S", ctx->certification_public_key)) {
		goto abort;
	}

	for(size_t i = 0; i<sizeof(DOPE_ROLE_KEY_REQUIREMENTS)/sizeof(DOPE_ROLE_KEY_REQUIREMENTS[0]); i++) {
		if(roles & (1<<DOPE_ROLE_KEY_REQUIREMENTS[i].role)) {
			for(size_t j = 0; j<sizeof(DOPE_ROLE_KEY_REQUIREMENTS[i].keys)/sizeof(DOPE_ROLE_KEY_REQUIREMENTS[i].keys[0]); j++) {
				if(DOPE_ROLE_KEY_REQUIREMENTS[i].keys[j] == DOPE_SECRET_KEY_TYPE_INVALID) {
					continue;
				}
				struct dope_secret_key *k = _find_secret_key(n, DOPE_ROLE_KEY_REQUIREMENTS[i].keys[j], DOPE_SECRET_KEY_VERSION_FIRST);
				if(k == NULL) {
					if(_copy_secret_key(n, ctx, DOPE_ROLE_KEY_REQUIREMENTS[i].keys[j]) < 0) {
						goto abort;
					}
				}
			}
		}
	}

	n->aid = ctx->aid;
	n->use_uid = ctx->use_uid;
	n->force_uid = ctx->force_uid;
	n->roles_initialized = roles;
	error = 0;

abort:
	if(error) {
		_free_context(n);
		return NULL;
	}

	return n;

}

int dope_create_credit(dope_context_t ctx, const char *config, uint32_t id)
{
	if(ctx == NULL || config == NULL) {
		return -1;
	}

	int retval = -1;
	struct dope_context *n = _copy_context_base(ctx, 1<<DOPE_ROLE_CREDIT | 1<<DOPE_ROLE_LIMITED_CREDIT | 1<<DOPE_ROLE_DEBIT);

	n->identity.key_identifier = id;
	n->identity.key_flags = DOPE_CERTIFICATE_KEY_FLAG_DEBIT | DOPE_CERTIFICATE_KEY_FLAG_LIMITED_CREDIT | DOPE_CERTIFICATE_KEY_FLAG_CREDIT;
	if(_sign_identity(ctx, &n->identity) < 0) {
		goto abort;
	}

	retval = _write_config(n, config);

abort:
	_free_context(n);

	return retval;
}

int dope_create_limited_credit(dope_context_t ctx, const char *config, uint32_t id)
{
	if(ctx == NULL || config == NULL) {
		return -1;
	}

	int retval = -1;
	struct dope_context *n = _copy_context_base(ctx, 1<<DOPE_ROLE_LIMITED_CREDIT | 1<<DOPE_ROLE_DEBIT);

	n->identity.key_identifier = id;
	n->identity.key_flags = DOPE_CERTIFICATE_KEY_FLAG_DEBIT | DOPE_CERTIFICATE_KEY_FLAG_LIMITED_CREDIT;
	if(_sign_identity(ctx, &n->identity) < 0) {
		goto abort;
	}

	retval = _write_config(n, config);

abort:
	_free_context(n);

	return retval;
}

int dope_create_debit(dope_context_t ctx, const char *config, uint32_t id)
{
	if(ctx == NULL || config == NULL) {
		return -1;
	}

	int retval = -1;
	struct dope_context *n = _copy_context_base(ctx, 1<<DOPE_ROLE_DEBIT);

	n->identity.key_identifier = id;
	n->identity.key_flags = DOPE_CERTIFICATE_KEY_FLAG_DEBIT;
	if(_sign_identity(ctx, &n->identity) < 0) {
		goto abort;
	}

	retval = _write_config(n, config);

abort:
	_free_context(n);

	return retval;
}

static int _parse_config(dope_context_t ctx, const char *config)
{
	int retval = -1;
	cfg_t *cfg = NULL;

	cfg = cfg_init(dope_opts, CFGF_NONE);
	if(cfg == NULL) {
		goto abort;
	}

	// FIXME Set validators: pub/priv only in certificate, format of pub/priv, title of key section, roles, flags, aid

	if(cfg_parse(cfg, config) != CFG_SUCCESS) {
		goto abort;
	}

	// First: Load identity
	cfg_t *cfg_identity = cfg_getsec(cfg, "identity");
	if(cfg_identity == NULL) {
		cfg_error(cfg, "section 'identity' must be present");
		goto abort;
	}

	if(cfg_getint(cfg_identity, "identifier") < 0 || cfg_getint(cfg_identity, "identifier") > 0xFFFFFFFFUL) {
		cfg_error(cfg_identity, "valid value for 'identifier' in section 'identity' must be present");
		goto abort;
	}
	ctx->identity.key_identifier = cfg_getint(cfg_identity, "identifier");

	const char *pubkey = cfg_getstr(cfg_identity, "public_key");
	if(pubkey == NULL || gcry_sexp_new(&ctx->identity.public_key, pubkey, strlen(pubkey), 1) < 0) {
		cfg_error(cfg_identity, "valid value for 'public_key' in section 'identity' must be present");
		goto abort;
	}

	const char *privkey = cfg_getstr(cfg_identity, "private_key");
	if(privkey == NULL || gcry_sexp_new(&ctx->identity.private_key, privkey, strlen(privkey), 1) < 0) {
		cfg_error(cfg_identity, "valid value for 'private_key' in section 'identity' must be present");
		goto abort;
	}

	const char *cert = cfg_getstr(cfg_identity, "certificate");
	if(cert == NULL || _parse_hex(cert, &ctx->identity.certificate, &ctx->identity.certificate_length, 0) < 0) {
		cfg_error(cfg_identity, "valid value for 'certificate' in section 'identity' must be present");
		goto abort;
	}

	for(size_t i = 0; i<cfg_size(cfg_identity, "flags"); i++) {
		const char *flag = cfg_getnstr(cfg_identity, "flags", i);
		for(size_t j = 0; j<sizeof(DOPE_KEY_FLAG_NAMES)/sizeof(DOPE_KEY_FLAG_NAMES[i]); j++) {
			if(strlen(flag) == strlen(DOPE_KEY_FLAG_NAMES[j].name) && strcmp(flag, DOPE_KEY_FLAG_NAMES[j].name) == 0) {
				ctx->identity.key_flags |= DOPE_KEY_FLAG_NAMES[j].flag;
			}
		}
	}

	// Second: Assign all the keys
	for(size_t i=0; i<cfg_size(cfg, "key"); i++) {
		cfg_t *cfg_key = cfg_getnsec(cfg, "key", i);
		const char *title = cfg_title(cfg_key);

		if(title == NULL) {
			cfg_error(cfg_key, "section 'key' must specify a key name");
			goto abort;
		}

		if(strcmp(title, "certification") == 0) {
			const char *pubkey = cfg_getstr(cfg_key, "public_key");
			if(pubkey == NULL || gcry_sexp_new(&ctx->certification_public_key, pubkey, strlen(pubkey), 1) < 0) {
				cfg_error(cfg_key, "valid value for 'public_key' in section 'key certification' must be present");
				goto abort;
			}

			const char *privkey = cfg_getstr(cfg_key, "private_key");
			if(privkey != NULL) {
				if(gcry_sexp_new(&ctx->certification_private_key, privkey, strlen(privkey), 1) < 0) {
					cfg_error(cfg_key, "value for 'private_key' in section 'key certification' must not be invalid");
					goto abort;
				}
			}
		} else {
			const char *underscore_pos = strrchr(title, '_');
			char *endptr = NULL;
			long version = 0;

			if(underscore_pos != NULL && underscore_pos[1] != 0) {
				version = strtol(underscore_pos+1, &endptr, 10);
			}

			if(underscore_pos == NULL || underscore_pos[1] == 0 || endptr[0] != 0) {
				cfg_error(cfg_key, "the name of a 'key' section must either be 'certification' or of the form type_version, not '%s'", title);
				goto abort;
			}

			if(version < 0 || version > 255) {
				cfg_error(cfg_key, "the key version in section 'key %s' exceeds the allowable values", title);
				goto abort;
			}

			size_t type_length = underscore_pos - title;
			bool added = 0;
			for(size_t j=0; j<sizeof(DOPE_SECRET_KEY_NAMES)/sizeof(DOPE_SECRET_KEY_NAMES[0]); j++) {
				if(DOPE_SECRET_KEY_NAMES[j] == NULL) {
					continue;
				}

				if(strlen(DOPE_SECRET_KEY_NAMES[j]) == type_length && strncmp(title, DOPE_SECRET_KEY_NAMES[j], type_length) == 0) {
					if(_parse_secret_key(ctx, j, version, cfg_getstr(cfg_key, "key")) < 0) {
						cfg_error(cfg_key, "valid value for 'key' in section 'key %s' must be present", title);
						goto abort;
					} else {
						added = 1;
						break;
					}
				}
			}

			if(!added) {
				cfg_error(cfg_key, "the name of a 'key' section must either be 'certification' or of the form type_version, not '%s'", title);
				goto abort;
			}
		}
	}

	// Third: Verify certificate
	if(_verify_identity(ctx, &ctx->identity) < 0) {
		cfg_error(cfg, "the identity certificate or certification public key are invalid and/or can not be used");
		goto abort;
	}

	// Fourth: Load common settings, and verify keys for all roles exist
	cfg_t *cfg_common = cfg_getsec(cfg, "common");
	if(cfg_common == NULL) {
		cfg_error(cfg, "section 'common' must be present");
		goto abort;
	}

	ctx->aid = cfg_getint(cfg_common, "aid");
	ctx->force_uid = cfg_getbool(cfg_common, "force_uid");
	ctx->use_uid = cfg_getbool(cfg_common, "use_uid");

	for(size_t i=0; i<cfg_size(cfg_common, "roles"); i++) {
		const char *role = cfg_getnstr(cfg_common, "roles", i);
		int role_index = -1;
		for(size_t j=0; j<sizeof(DOPE_ROLE_KEY_REQUIREMENTS)/sizeof(DOPE_ROLE_KEY_REQUIREMENTS[0]); j++) {
			if(strlen(role) == strlen(DOPE_ROLE_KEY_REQUIREMENTS[j].name) && strcmp(role, DOPE_ROLE_KEY_REQUIREMENTS[j].name) == 0) {
				role_index = j;
				break;
			}
		}
		if(role_index == -1) {
			cfg_error(cfg_common, "invalid value '%s' for 'roles' in section 'common'", role);
			goto abort;
		}

		if(DOPE_ROLE_KEY_REQUIREMENTS[role_index].need_certification_private) {
			if(ctx->certification_private_key == NULL || gcry_pk_testkey(ctx->certification_private_key) != 0) {
				cfg_error(cfg_common, "role '%s' needs a valid certification private key", role);
				goto abort;
			}
		}

		for(size_t j=0; j<sizeof(DOPE_ROLE_KEY_REQUIREMENTS[0].keys)/sizeof(DOPE_ROLE_KEY_REQUIREMENTS[0].keys[0]); j++) {
			if(DOPE_ROLE_KEY_REQUIREMENTS[role_index].keys[j] == DOPE_SECRET_KEY_TYPE_INVALID) {
				continue;
			}
			struct dope_secret_key *k = _find_secret_key(ctx, DOPE_ROLE_KEY_REQUIREMENTS[role_index].keys[j], DOPE_SECRET_KEY_VERSION_FIRST);
			if(k == NULL) {
				cfg_error(cfg_common, "role '%s' needs a secret key of type %s", role, DOPE_SECRET_KEY_NAMES[DOPE_ROLE_KEY_REQUIREMENTS[role_index].keys[j]]);
				goto abort;
			}
		}

		ctx->roles_initialized |= 1<<DOPE_ROLE_KEY_REQUIREMENTS[role_index].role;
	}

	retval = 0;

abort:
	if(cfg != NULL) {
		cfg_free(cfg);
	}
	return retval;
}

extern dope_context_t dope_init(const char *config, dope_log_cb_t log_callback, void *p)
{
	if(!_init_gcrypt()) {
		return NULL;
	}

	struct dope_context *result = gcry_calloc_secure(1, sizeof(*result));
	if(result == NULL) {
		return NULL;
	}

	if(_parse_config(result, config) < 0) {
		_free_context(result);
		return NULL;
	}

	result->log_callback = log_callback;
	result->log_callback_p = p;

	return result;
}

int dope_fini(dope_context_t ctx)
{
	if(ctx == NULL) {
		return -1;
	}

	_free_context(ctx);
	return 0;
}

