// SPDX-FileCopyrightText: 2026 Shubh Bhattacharya
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_HASH_FNV_H
#define RZ_HASH_FNV_H

#include <rz_types.h>

#define FNV1A_32_DIGEST_LENGTH 4

void fnv1a_32(const ut8 *data, size_t size, ut32 *result);

#endif /* RZ_HASH_FNV_H */