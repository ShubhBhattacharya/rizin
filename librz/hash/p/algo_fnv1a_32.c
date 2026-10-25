// SPDX-FileCopyrightText: 2026 Shubh Bhattacharya
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include "../algorithms/fnv/fnv.h"

typedef struct {
	ut8 *buffer;
	ut64 buffer_len;
	ut64 buffer_alloc;
} Fnv1a32Context;

static void *plugin_fnv1a_32_context_new() {
	return RZ_NEW0(Fnv1a32Context);
}

static void plugin_fnv1a_32_context_free(void *context) {
	if (context) {
		Fnv1a32Context *ctx = (Fnv1a32Context *)context;
		free(ctx->buffer);
		free(ctx);
	}
}

static RzHashSize plugin_fnv1a_32_digest_size(void *context) {
	return FNV1A_32_DIGEST_LENGTH;
}

static RzHashSize plugin_fnv1a_32_block_size(void *context) {
	return 1;
}

static bool plugin_fnv1a_32_init(void *context) {
	rz_return_val_if_fail(context, false);
	Fnv1a32Context *ctx = (Fnv1a32Context *)context;
	free(ctx->buffer);
	ctx->buffer = NULL;
	ctx->buffer_len = 0;
	ctx->buffer_alloc = 0;
	return true;
}

static bool plugin_fnv1a_32_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);
	Fnv1a32Context *ctx = (Fnv1a32Context *)context;

	ut64 new_len = ctx->buffer_len + size;
	if (new_len > ctx->buffer_alloc) {
		ut64 new_alloc = RZ_MAX(new_len, ctx->buffer_alloc * 2);
		ut8 *tmp = realloc(ctx->buffer, new_alloc);
		if (!tmp) {
			return false;
		}
		ctx->buffer = tmp;
		ctx->buffer_alloc = new_alloc;
	}
	memcpy(ctx->buffer + ctx->buffer_len, data, size);
	ctx->buffer_len = new_len;
	return true;
}

static bool plugin_fnv1a_32_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);
	Fnv1a32Context *ctx = (Fnv1a32Context *)context;

	ut32 result = 0;
	ut8 empty = 0;
	fnv1a_32(ctx->buffer ? ctx->buffer : &empty, (size_t)ctx->buffer_len, &result);
	rz_write_be32(digest, result);
	return true;
}

static bool plugin_fnv1a_32_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(FNV1A_32_DIGEST_LENGTH);
	if (!dgst) {
		return false;
	}

	ut32 result = 0;
	fnv1a_32(data, (size_t)size, &result);
	rz_write_be32(dgst, result);

	*digest = dgst;
	if (digest_size) {
		*digest_size = FNV1A_32_DIGEST_LENGTH;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_fnv1a_32 = {
	.name = "fnv1a-32",
	.author = "Glenn Fowler, Landon Curt Noll, Phong Vo",
	.license = "Public Domain",
	.description = "Fowler-Noll-Vo 1a 32-bit non-cryptographic hash",
	.support_hmac = false,
	.context_new = plugin_fnv1a_32_context_new,
	.context_free = plugin_fnv1a_32_context_free,
	.digest_size = plugin_fnv1a_32_digest_size,
	.block_size = plugin_fnv1a_32_block_size,
	.init = plugin_fnv1a_32_init,
	.update = plugin_fnv1a_32_update,
	.final = plugin_fnv1a_32_final,
	.small_block = plugin_fnv1a_32_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_fnv1a_32,
	.version = RZ_VERSION
};
#endif