#pragma once

#include <stdint.h>

uint16_t freeze16 (uint16_t x);

uint16_t kyber_montgomery_reduce (uint32_t a);

uint16_t barrett_reduce (uint16_t a);
