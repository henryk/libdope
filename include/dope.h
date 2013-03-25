#ifndef DOPE_H
#define DOPE_H

#include <stdint.h>
#include <stdio.h>
#include <nfc/nfc.h>
#include <freefare.h>

typedef struct dope_context *dope_context_t;
typedef struct dope_connection *dope_connection_t;

struct dope_card_state {
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

extern dope_context_t dope_init(const char *config);
extern int dope_fini(dope_context_t ctx);

extern int dope_create_master(const char *config);
extern int dope_create_debit(dope_context_t ctx, const char *config);
extern int dope_create_credit(dope_context_t ctx, const char *config);
extern int dope_create_limited_credit(dope_context_t ctx, const char *config);

extern dope_connection_t dope_connect_any(dope_context_t ctx, nfc_context *nfc_context);
extern dope_connection_t dope_connect(dope_context_t ctx, MifareTag tag);
extern dope_connection_t dope_disconnect(dope_connection_t con);

extern int dope_format(dope_connection_t con, int32_t value, int32_t max_value, int enable_limited_credit, struct dope_card_state *state, char **log);

extern int dope_get(dope_connection_t con, struct dope_card_state *state);
extern int dope_transaction_prepare(dope_connection_t con, enum dope_transaction_type transaction_type, int32_t value, char **log);
extern int dope_transaction_commit(dope_connection_t con, char **log);
extern int dope_transaction_abort(dope_connection_t con, char **log);


#endif
