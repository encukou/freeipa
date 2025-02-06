#undef NDEBUG
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>

static OSSL_FUNC_rand_newctx_fn mock_rand_newctx;
static OSSL_FUNC_rand_freectx_fn mock_rand_freectx;
static OSSL_FUNC_rand_instantiate_fn mock_rand_instantiate;
static OSSL_FUNC_rand_uninstantiate_fn mock_rand_uninstantiate;
static OSSL_FUNC_rand_generate_fn mock_rand_generate;
static OSSL_FUNC_rand_enable_locking_fn mock_rand_enable_locking;
static OSSL_FUNC_rand_gettable_ctx_params_fn mock_rand_gettable_ctx_params;
static OSSL_FUNC_rand_get_ctx_params_fn mock_rand_get_ctx_params;

static void *
mock_rand_newctx(void *provctx, void *parent,
                 const OSSL_DISPATCH *parent_calls)
{
	int *ctx = OPENSSL_zalloc(sizeof(*ctx));
	assert(ctx);
	return ctx;
}

static void
mock_rand_freectx(void *vctx)
{
	int *ctx = vctx;
	OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static int
mock_rand_instantiate(void *ctx, unsigned int strength,
                      int prediction_resistance,
                      const unsigned char *pstr, size_t pstr_len,
                      const OSSL_PARAM params[])
{
	return 1;
}

static int
mock_rand_uninstantiate(void *ctx)
{
	return 1;
}

static int
mock_rand_generate(void *ctx, unsigned char *out, size_t outlen,
                   unsigned int strength, int prediction_resistance,
                   const unsigned char *adin, size_t adinlen)
{
	for (size_t i = 0; i < outlen; i++)
		out[i] = (unsigned char)rand();
	return 1;
}

static int
mock_rand_enable_locking(void *ctx)
{
	return 1;
}

static const OSSL_PARAM *
mock_rand_gettable_ctx_params(void *ctx, void *provctx)
{
	static const OSSL_PARAM known_gettable_ctx_params[] = {
		OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
		OSSL_PARAM_END
	};
	return known_gettable_ctx_params;
}

static int
mock_rand_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
	OSSL_PARAM *p;
	p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, SIZE_MAX))
		return 0;
	return 1;
}

static const OSSL_DISPATCH mock_rand_functions[] = {
	{ OSSL_FUNC_RAND_NEWCTX, (void(*)(void))mock_rand_newctx },
	{ OSSL_FUNC_RAND_FREECTX, (void(*)(void))mock_rand_freectx },
	{ OSSL_FUNC_RAND_INSTANTIATE, (void(*)(void))mock_rand_instantiate },
	{ OSSL_FUNC_RAND_UNINSTANTIATE, (void(*)(void))mock_rand_uninstantiate },
	{ OSSL_FUNC_RAND_GENERATE, (void(*)(void))mock_rand_generate },
	{ OSSL_FUNC_RAND_ENABLE_LOCKING, (void(*)(void))mock_rand_enable_locking },
	{ OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void(*)(void))mock_rand_gettable_ctx_params },
	{ OSSL_FUNC_RAND_GET_CTX_PARAMS, (void(*)(void))mock_rand_get_ctx_params },
	{ 0, NULL }
};


static const OSSL_ALGORITHM mock_rand[] = {
	{ "MOCK", "provider=mock", mock_rand_functions },
	{ NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *
mock_provider_query(void *provctx, int id, int *no_cache)
{
	*no_cache = 0;
	return id == OSSL_OP_RAND ? mock_rand : NULL;
}

static const OSSL_DISPATCH mock_provider[] = {
	{ OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))OSSL_LIB_CTX_free },
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))mock_provider_query },
	{ 0, NULL }
};

static int
mock_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
	       	   const OSSL_DISPATCH **out, void **provctx)
{
	if ((*provctx = OSSL_LIB_CTX_new()) == NULL)
		return 0;
	*out = mock_provider;
	return 1;
}

ssize_t __attribute__((visibility("protected")))
getrandom(void *buf, size_t buflen, unsigned int flags)
{
	if (buflen > INT_MAX || RAND_bytes(buf, buflen) != 1)
		return -1;
	return (ssize_t)buflen;
}

int __attribute__ ((visibility ("protected")))
RAND_bytes (unsigned char *buf, int num)
{
    memset (buf, 0x1, num);
    return 1;
}

void __attribute__ ((visibility ("protected")))
arc4random_buf(void *buf, size_t nbytes)
{
	memset (buf, 0x1, nbytes);
}

static void __attribute__((constructor))
install_mock_provider(void)
{
	srand(0x12345678);
	assert(OSSL_PROVIDER_add_builtin(NULL, "mock", mock_provider_init));
	assert(RAND_set_DRBG_type(NULL, "mock", NULL, NULL, NULL));
	assert(OSSL_PROVIDER_try_load(NULL, "mock", 1));
}
