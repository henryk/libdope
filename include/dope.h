#ifndef DOPE_H
#define DOPE_H

#include <stdint.h>
#include <stdio.h>
#include <nfc/nfc.h>
#include <freefare.h>

typedef struct dope_context *dope_context_t;
typedef struct dope_connection *dope_connection_t;

enum dope_connection_state {
	DOPE_CONNECTION_STATE_INVALID = 0,         /* No card or no application on card */
	DOPE_CONNECTION_STATE_PRESENT,             /* Card and application present */
	DOPE_CONNECTION_STATE_AUTHENTICATED,       /* Authentication with Identification key (mode A) or Debit key (mode D) ok */
	DOPE_CONNECTION_STATE_READ,                /* Identification and balance data read and verified */
	DOPE_CONNECTION_STATE_TRANSACTION_PENDING, /* A transaction is pending, need commit or abort */
	DOPE_CONNECTION_STATE_ERROR,               /* Plausibility error on data, verification error on signature or integrity error on radio interface */
};

struct dope_card_state {
	enum dope_connection_state connection_state;
	size_t instance_identifier_length;
	char instance_identifier[36];

	int32_t value;
	int32_t max_value;

	uint32_t signed_by;
};

enum dope_role {
	DOPE_ROLE_MASTER = 0,
	DOPE_ROLE_DEBIT = 1,
	DOPE_ROLE_CREDIT = 2,
	DOPE_ROLE_LIMITED_CREDIT = 3,
	DOPE_ROLE_CERTIFIER = 4,
};

enum dope_transaction_type {
	DOPE_TRANSACTION_TYPE_INVALID = 0,
	DOPE_TRANSACTION_TYPE_CREDIT = 1,
	DOPE_TRANSACTION_TYPE_DEBIT = 2,
	DOPE_TRANSACTION_TYPE_LIMITED_CREDIT = 3,
};

#define DOPE_ERROR_GENERAL_ERROR -1
#define DOPE_ERROR_VALUE_UNDERFLOW -2
#define DOPE_ERROR_VALUE_OVERFLOW -3

typedef int(*dope_log_cb_t)(const char *msg, void *p);

extern dope_context_t dope_init(const char *config, dope_log_cb_t log_callback, void *p);
extern int dope_fini(dope_context_t ctx);

extern int dope_create_master(const char *config);
extern int dope_create_debit(dope_context_t ctx, const char *config, uint32_t id);
extern int dope_create_credit(dope_context_t ctx, const char *config, uint32_t id);
extern int dope_create_limited_credit(dope_context_t ctx, const char *config, uint32_t id);

extern dope_connection_t dope_connect_any(dope_context_t ctx, nfc_context *nfc_context);
extern dope_connection_t dope_connect(dope_context_t ctx, MifareTag tag);
extern dope_connection_t dope_disconnect(dope_connection_t con);

extern int dope_format(dope_connection_t con, int32_t value, int32_t max_value, int enable_limited_credit, struct dope_card_state *state);

extern int dope_get(dope_connection_t con, struct dope_card_state *state);
extern int dope_transaction_prepare(dope_connection_t con, enum dope_transaction_type transaction_type, int32_t value);
extern int dope_transaction_commit(dope_connection_t con);
extern int dope_transaction_abort(dope_connection_t con);


#endif
