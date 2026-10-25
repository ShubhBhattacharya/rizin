// SPDX-FileCopyrightText: 2026 Shubh Bhattacharya
// SPDX-License-Identifier: LGPL-3.0-only

#include "fnv.h"

#define FNV_OFFSET_BASIS_32 2166136261U
#define FNV_PRIME_32        16777619U

void fnv1a_32(const ut8 *data, size_t size, ut32 *result) {
	if (!result) {
		return;
	}
	ut32 hash = FNV_OFFSET_BASIS_32;
	if (data) {
		for (size_t i = 0; i < size; i++) {
			hash ^= data[i];
			hash *= FNV_PRIME_32;
		}
	}
	*result = hash;
}