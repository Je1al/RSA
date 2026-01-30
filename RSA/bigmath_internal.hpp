#ifndef BIGMATH_INTERNAL_HPP
#define BIGMATH_INTERNAL_HPP

#include "bigmath.hpp"

    BigInt exported_internal_sub(const BigInt& a, const BigInt& b);
    BigInt exported_internal_add(const BigInt& a, const BigInt& b);
    BigInt exported_big_lshift(const BigInt& a, size_t bits);
    BigInt exported_big_rshift(const BigInt& a, size_t bits);
    BigInt exported_mod_inverse_binary(const BigInt& a, const BigInt& m);
    BigInt exported_gcd_euclidean(const BigInt& a, const BigInt& b);
    bool exported_is_even(const BigInt& a);
    size_t exported_count_bits(const BigInt& a);
    bool exported_get_bigint_bit(const BigInt& a, size_t index);
    BigInt exported_generate_random_bigint(size_t bits);
    BigInt exported_random_in_range(const BigInt& min, const BigInt& max);


#endif // BIGMATH_INTERNAL_HPP