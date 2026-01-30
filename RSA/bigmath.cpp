#include "bigmath.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <vector>
#include <algorithm>
#include <memory>
#include <cctype>
#include <limits>
#include <cmath>
#include <cstring>
#include <random>
#include <chrono>

namespace {

    // =========================================================================
    //  -- BIGINT
    // =========================================================================

    
    constexpr size_t   WORD_BITS = 32;
    constexpr uint64_t WORD_BASE = 1ULL << WORD_BITS;
    constexpr uint32_t MAX_WORD = 0xFFFFFFFF;

  
    struct BigIntAccess
    {
        uint32_t* digits_;
        size_t length_;
        int sign_;
    };


#define GET_ACCESS(a) (*reinterpret_cast<BigIntAccess*>(&a))
#define GET_CONST_ACCESS(a) (*reinterpret_cast<const BigIntAccess*>(const_cast<BigInt*>(&a)))

// =========================================================================
// BIGINT
// =========================================================================

    void normalize(BigInt& a) {
        BigIntAccess& acc = GET_ACCESS(a);
        while (acc.length_ > 0 && acc.digits_[acc.length_ - 1] == 0) {
            acc.length_--;
        }
        if (acc.length_ == 0) {
            acc.sign_ = 0;
        }
    }

    BigInt internal_sub(const BigInt& a, const BigInt& b) {
        const BigIntAccess& acc_a = GET_CONST_ACCESS(a);
        const BigIntAccess& acc_b = GET_CONST_ACCESS(b);

        size_t len = std::max(acc_a.length_, acc_b.length_);
        BigInt result(len);
        BigIntAccess& acc_res = GET_ACCESS(result);
        uint64_t borrow = 0;

        for (size_t i = 0; i < len; ++i) {

            uint64_t a_val = (i < acc_a.length_) ? acc_a.digits_[i] : 0;
            uint64_t b_val = (i < acc_b.length_) ? acc_b.digits_[i] : 0;

            int64_t diff = (int64_t)a_val - (int64_t)b_val - borrow;

            if (diff < 0) {
                diff += WORD_BASE;
                borrow = 1;
            }
            else {
                borrow = 0;
            }

            acc_res.digits_[i] = (uint32_t)diff;
        }

        acc_res.length_ = len;
        normalize(result);

        acc_res.sign_ = 1;
        return result;
    }

    BigInt internal_add(const BigInt& a, const BigInt& b) {
        const BigIntAccess& acc_a = GET_CONST_ACCESS(a);
        const BigIntAccess& acc_b = GET_CONST_ACCESS(b);

        size_t len = std::max(acc_a.length_, acc_b.length_);
        BigInt result(len + 1);
        BigIntAccess& acc_res = GET_ACCESS(result);
        uint64_t carry = 0;

        for (size_t i = 0; i < len; ++i) {
            uint64_t sum = carry;
            if (i < acc_a.length_) sum += acc_a.digits_[i];
            if (i < acc_b.length_) sum += acc_b.digits_[i];

            acc_res.digits_[i] = (uint32_t)(sum & MAX_WORD);
            carry = sum >> WORD_BITS;
        }

        if (carry > 0) {
            acc_res.digits_[len] = (uint32_t)carry;
            acc_res.length_ = len + 1;
        }
        else {
            acc_res.length_ = len;
        }
        normalize(result);
        acc_res.sign_ = 1;
        return result;
    }

    BigInt big_lshift(const BigInt& a, size_t bits) {
        const BigIntAccess& acc_a = GET_CONST_ACCESS(a);
        if (acc_a.length_ == 0) return a;

        size_t word_shift = bits / WORD_BITS;
        size_t bit_shift = bits % WORD_BITS;

        size_t new_len = acc_a.length_ + word_shift + 1;
        BigInt result(new_len);
        BigIntAccess& acc_res = GET_ACCESS(result);
        acc_res.sign_ = acc_a.sign_;

        for (size_t i = 0; i < acc_a.length_; ++i) {
            acc_res.digits_[i + word_shift] = acc_a.digits_[i];
        }
        
        if (bit_shift > 0) {
            uint64_t carry = 0;
            for (size_t i = word_shift; i < new_len; ++i) {
                uint64_t val = ((uint64_t)acc_res.digits_[i] << bit_shift) | carry;
                acc_res.digits_[i] = (uint32_t)(val & MAX_WORD);
                carry = val >> WORD_BITS;
            }
        }

        acc_res.length_ = new_len;
        normalize(result);
        return result;
    }


    BigInt big_rshift(const BigInt& a, size_t bits) {
        const BigIntAccess& acc_a = GET_CONST_ACCESS(a);
        if (acc_a.length_ == 0) return a;

        size_t word_shift = bits / WORD_BITS;
        size_t bit_shift = bits % WORD_BITS;

        if (word_shift >= acc_a.length_) return BigInt(0);

        size_t new_len = acc_a.length_ - word_shift;
        BigInt result(new_len);
        BigIntAccess& acc_res = GET_ACCESS(result);
        acc_res.sign_ = acc_a.sign_;


        for (size_t i = 0; i < new_len; ++i) {
            acc_res.digits_[i] = acc_a.digits_[i + word_shift];
        }

        if (bit_shift > 0) {
            for (size_t i = 0; i < new_len - 1; ++i) {
            
                acc_res.digits_[i] = (acc_res.digits_[i] >> bit_shift) |
                    (acc_res.digits_[i + 1] << (WORD_BITS - bit_shift));
            }
            acc_res.digits_[new_len - 1] >>= bit_shift;
        }

        acc_res.length_ = new_len;
        normalize(result);
        return result;
    }

    // =========================================================================
    //
    // =========================================================================

    BigInt mod_inverse_binary(const BigInt& a, const BigInt& m) {

        BigInt m0 = m;
        BigInt y = BigInt::fromU64(0);
        BigInt x = BigInt::fromU64(1);

        if (m.cmp(BigInt::fromU64(1)) == 0) {
            return BigInt::fromU64(0);
        }

        BigInt a0 = a;

        while (a0.cmp(BigInt::fromU64(1)) > 0) {
            // q = a0 / m0
            BigInt q = BigInt::divmod(a0, m0, nullptr);

            // t = m0
            BigInt t = m0;

            // m0 = a0 % m0
            m0 = BigInt::modNaive(a0, m0);
            a0 = t;

            t = y;

            // y = x - q * y
            BigInt qy = BigInt::mulNaive(q, y);

            if (x.cmp(qy) >= 0) {
                y = internal_sub(x, qy);
            }
            else {
               
                BigInt diff = internal_sub(qy, x);
                BigInt temp_y = m;

                while (temp_y.cmp(diff) < 0) {
                    temp_y = internal_add(temp_y, m);
                }

                y = internal_sub(temp_y, diff);
            }

            x = t;
        }

        while (x.cmp(BigInt::fromU64(0)) < 0) {
            x = internal_add(x, m);
        }

        while (x.cmp(m) >= 0) {
            x = internal_sub(x, m);
        }

        return x;
    }

    uint32_t mod_inverse_u32(uint32_t a) {
        if ((a & 1) == 0) return 0;
        uint32_t x = 1;
        for (int i = 0; i < 5; i++) {
            x = x * (2 - a * x);
        }
        return x;
    }

    bool get_bigint_bit(const BigInt& a, size_t index) {
        const BigIntAccess& acc_a = GET_CONST_ACCESS(a);
        size_t word_index = index / WORD_BITS;
        size_t bit_index = index % WORD_BITS;

        if (word_index >= acc_a.length_) return false;
        return (acc_a.digits_[word_index] >> bit_index) & 1;
    }

    size_t count_bits(const BigInt& a) {
        const BigIntAccess& acc_a = GET_CONST_ACCESS(a);
        if (acc_a.length_ == 0) return 0;

        size_t bits = (acc_a.length_ - 1) * WORD_BITS;
        uint32_t top_word = acc_a.digits_[acc_a.length_ - 1];
        while (top_word) {
            bits++;
            top_word >>= 1;
        }
        return bits;
    }

    // =========================================================================
    // HELPER FUNCTIONS FOR RSA
    // =========================================================================

    // Generate random BigInt with specified bit length
    BigInt generate_random_bigint(size_t bits) {
        if (bits == 0) return BigInt(0);

        // Calculate required number of words
        size_t words = (bits + WORD_BITS - 1) / WORD_BITS;
        size_t bits_last_word = bits % WORD_BITS;
        if (bits_last_word == 0) bits_last_word = WORD_BITS;

        BigInt result(words);
        BigIntAccess& acc = GET_ACCESS(result);

        // Random number generator
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> dis(0, MAX_WORD);

        // Fill words with random values
        for (size_t i = 0; i < words; ++i) {
            acc.digits_[i] = dis(gen);
        }

        // Mask the most significant word to get the required bit length
        if (bits_last_word < WORD_BITS) {
            uint32_t mask = (1u << bits_last_word) - 1;
            acc.digits_[words - 1] &= mask;
        }

        // Set the most significant bit to 1 to ensure the required length
        acc.digits_[words - 1] |= (1u << (bits_last_word - 1));

        normalize(result);
        acc.sign_ = 1;
        return result;
    }

    // Check if a number is even
    bool is_even(const BigInt& a) {
        const BigIntAccess& acc = GET_CONST_ACCESS(a);
        if (acc.length_ == 0) return true; // 0 is considered even
        return (acc.digits_[0] & 1) == 0;
    }

    // Find greatest common divisor using Euclidean algorithm
    BigInt gcd_euclidean(const BigInt& a, const BigInt& b) {
        if (b.cmp(BigInt::fromU64(0)) == 0) return a;
        BigInt a_mod_b = BigInt::modNaive(a, b);
        return gcd_euclidean(b, a_mod_b);
    }

    // Generate random number in range [min, max]
    BigInt random_in_range(const BigInt& min, const BigInt& max) {
        if (max.cmp(min) <= 0) return min;

        // Calculate range
        BigInt range = internal_sub(max, min);

        // Generate random number and take modulo range
        size_t bits = count_bits(range);
        BigInt random_num;

        do {
            random_num = generate_random_bigint(bits);
        } while (random_num.cmp(range) >= 0);

        // Add minimum value
        return internal_add(random_num, min);
    }

} // namespace

BigInt exported_internal_sub(const BigInt& a, const BigInt& b) {
    return internal_sub(a, b);
}

BigInt exported_internal_add(const BigInt& a, const BigInt& b) {
    return internal_add(a, b);
}

BigInt exported_big_lshift(const BigInt& a, size_t bits) {
    return big_lshift(a, bits);
}

BigInt exported_big_rshift(const BigInt& a, size_t bits) {
    return big_rshift(a, bits);
}

BigInt exported_mod_inverse_binary(const BigInt& a, const BigInt& m) {
    return mod_inverse_binary(a, m);
}

BigInt exported_gcd_euclidean(const BigInt& a, const BigInt& b) {
    return gcd_euclidean(a, b);
}

bool exported_is_even(const BigInt& a) {
    return is_even(a);
}

size_t exported_count_bits(const BigInt& a) {
    return count_bits(a);
}

bool exported_get_bigint_bit(const BigInt& a, size_t index) {
    return get_bigint_bit(a, index);
}

BigInt exported_generate_random_bigint(size_t bits) {
    return generate_random_bigint(bits);
}

BigInt exported_random_in_range(const BigInt& min, const BigInt& max) {
    return random_in_range(min, max);
}

// =========================================================================
// IMPLEMENTATION OF BIGINT CLASS
// =========================================================================

// Default constructor - creates number with specified number of words
BigInt::BigInt(size_t words) : digits_(nullptr), length_(0), sign_(0) {
    BigIntAccess& acc = GET_ACCESS(*this);
    if (words > 0) {
        acc.digits_ = new uint32_t[words]();  // Allocate memory and initialize with zeros
        acc.length_ = words;
        acc.sign_ = 1;  // Positive number
    }
}

// Constructor from hexadecimal string
BigInt::BigInt(const std::string& hexstr) : digits_(nullptr), length_(0), sign_(0) {
    std::string s = hexstr;
    // Remove "0x" or "0X" prefix if present
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s = s.substr(2);
    }

    // Empty string = 0
    if (s.empty()) {
        BigIntAccess& acc = GET_ACCESS(*this);
        acc.digits_ = new uint32_t[1]();
        acc.length_ = 1;
        acc.sign_ = 0;
        return;
    }

    // Calculate required number of words (8 hex digits = 1 word)
    size_t hexDigits = s.length();
    size_t words = (hexDigits + 7) / 8;
    BigIntAccess& acc = GET_ACCESS(*this);

    acc.digits_ = new uint32_t[words]();
    acc.length_ = words;
    acc.sign_ = 1;  // Positive number

    // Parse string from the end (least significant digits first)
    for (size_t i = 0; i < hexDigits; ++i) {
        char c = s[hexDigits - 1 - i];  // Read from end of string
        if (!isxdigit(c)) {
            throw std::invalid_argument("Invalid hex character");
        }
        uint8_t value = 0;
        // Convert hex character to number
        if (c >= '0' && c <= '9') value = c - '0';
        else if (c >= 'a' && c <= 'f') value = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') value = c - 'A' + 10;
        else throw std::invalid_argument("Invalid hex digit");

        size_t wordIndex = i / 8;        // Word index
        size_t bitShift = (i % 8) * 4;   // Shift within word (4 bits per hex digit)

        // Add digit to corresponding word
        acc.digits_[wordIndex] |= (static_cast<uint32_t>(value) << bitShift);
    }
    normalize(*this);  // Remove leading zeros
}

// Create BigInt from decimal string
BigInt BigInt::fromDec(const std::string& decstr) {
    std::string s = decstr;
    if (s.empty()) return BigInt(0);

    // Remove all non-digit characters
    s.erase(std::remove_if(s.begin(), s.end(), [](char c) { return !std::isdigit(c); }), s.end());
    if (s.empty()) return BigInt(0);

    BigInt result(0);  // Start with zero
    BigInt ten = BigInt::fromU64(10);  // Constant 10

    // Process each digit
    for (char c : s) {
        result = BigInt::mulNaive(result, ten);  // Multiply current result by 10
        BigInt digit = BigInt::fromU64(c - '0'); // Current digit
        result = internal_add(result, digit);    // Add digit
    }
    return result;
}

// Create BigInt from uint64_t
BigInt BigInt::fromU64(uint64_t v) {
    if (v == 0) return BigInt(0);  // Zero

    // Determine required number of words
    size_t words = (v > MAX_WORD) ? 2 : 1;
    BigInt result(words);
    BigIntAccess& acc_res = GET_ACCESS(result);

    // Fill least significant word
    acc_res.digits_[0] = static_cast<uint32_t>(v & MAX_WORD);
    if (words > 1) {
        // Fill most significant word if needed
        acc_res.digits_[1] = static_cast<uint32_t>(v >> WORD_BITS);
    }
    normalize(result);
    return result;
}

// Copy constructor
BigInt::BigInt(const BigInt& other) : digits_(nullptr), length_(0), sign_(other.sign_) {
    const BigIntAccess& acc_other = GET_CONST_ACCESS(other);
    BigIntAccess& acc = GET_ACCESS(*this);

    if (acc_other.length_ > 0) {
        // Allocate memory and copy data
        acc.digits_ = new uint32_t[acc_other.length_];
        acc.length_ = acc_other.length_;
        std::copy(acc_other.digits_, acc_other.digits_ + acc_other.length_, acc.digits_);
    }
}

// Assignment operator
BigInt& BigInt::operator=(const BigInt& other) {
    if (this != &other) {
        BigIntAccess& acc = GET_ACCESS(*this);
        const BigIntAccess& acc_other = GET_CONST_ACCESS(other);

        // Free old memory
        delete[] acc.digits_;
        acc.digits_ = nullptr;
        acc.length_ = 0;
        acc.sign_ = acc_other.sign_;

        // Copy data if exists
        if (acc_other.length_ > 0) {
            acc.digits_ = new uint32_t[acc_other.length_];
            acc.length_ = acc_other.length_;
            std::copy(acc_other.digits_, acc_other.digits_ + acc_other.length_, acc.digits_);
        }
    }
    return *this;
}

// Destructor
BigInt::~BigInt() {
    BigIntAccess& acc = GET_ACCESS(*this);
    acc.digits_ = nullptr;
    acc.length_ = 0;
    acc.sign_ = 0;
    delete[] acc.digits_;  // Free memory
}

// Convert to hexadecimal string
std::string BigInt::toHex() const {
    const BigIntAccess& acc = GET_CONST_ACCESS(*this);
    if (acc.length_ == 0 || acc.sign_ == 0) return "0";  // Zero

    std::stringstream ss;
    ss << std::hex;

    // First word without leading zeros
    ss << acc.digits_[acc.length_ - 1];

    // Remaining words with leading zeros
    for (size_t i = acc.length_ - 1; i > 0; --i) {
        ss << std::setw(8) << std::setfill('0') << acc.digits_[i - 1];
    }

    std::string result = ss.str();
    // Remove possible leading zeros
    size_t start = result.find_first_not_of('0');
    if (start == std::string::npos) return "0";
    return result.substr(start);
}

// Convert to uint64_t (with overflow check)
uint64_t BigInt::toU64OrDie() const {
    const BigIntAccess& acc = GET_CONST_ACCESS(*this);
    if (acc.length_ > 2) throw std::overflow_error("BigInt too large for uint64_t");

    uint64_t result = 0;
    if (acc.length_ >= 1) result = acc.digits_[0];                    // Least significant word
    if (acc.length_ >= 2) result |= static_cast<uint64_t>(acc.digits_[1]) << 32;  // Most significant word
    return result;
}

// Compare two BigInts (analog of strcmp)
int BigInt::cmp(const BigInt& other) const {
    const BigIntAccess& acc = GET_CONST_ACCESS(*this);
    const BigIntAccess& acc_other = GET_CONST_ACCESS(other);

    // Compare length (more length = larger number)
    if (acc.length_ > acc_other.length_) return 1;
    if (acc.length_ < acc_other.length_) return -1;

    // Digit-by-digit comparison from most significant
    for (size_t i = acc.length_; i > 0; --i) {
        uint32_t a = acc.digits_[i - 1];
        uint32_t b = acc_other.digits_[i - 1];
        if (a > b) return 1;
        if (a < b) return -1;
    }
    return 0;  // Equal
}

// Comparison operators
bool BigInt::operator==(const BigInt& other) const { return cmp(other) == 0; }
bool BigInt::operator!=(const BigInt& other) const { return cmp(other) != 0; }

// Naive multiplication (schoolbook algorithm)
BigInt BigInt::mulNaive(const BigInt& a, const BigInt& b) {
    const BigIntAccess& acc_a = GET_CONST_ACCESS(a);
    const BigIntAccess& acc_b = GET_CONST_ACCESS(b);

    if (acc_a.length_ == 0 || acc_b.length_ == 0) return BigInt(0);  // Multiply by 0

    size_t len_a = acc_a.length_;
    size_t len_b = acc_b.length_;
    BigInt result(len_a + len_b);  // Result can be length a+b
    BigIntAccess& acc_res = GET_ACCESS(result);

    // Multiplication in columns
    for (size_t i = 0; i < len_a; ++i) {
        uint64_t carry = 0;
        for (size_t j = 0; j < len_b; ++j) {
            // Multiply digits and add carry
            uint64_t product = (uint64_t)acc_a.digits_[i] * acc_b.digits_[j];
            uint64_t sum = product + acc_res.digits_[i + j] + carry;

            acc_res.digits_[i + j] = (uint32_t)(sum & MAX_WORD);  // Lower 32 bits
            carry = sum >> WORD_BITS;  // Carry
        }
        if (carry > 0) {
            acc_res.digits_[i + len_b] = (uint32_t)carry;  // Store remaining carry
        }
    }

    acc_res.length_ = len_a + len_b;
    normalize(result);
    return result;
}

// Naive modulo operation (sequential subtraction)
BigInt BigInt::modNaive(const BigInt& a, const BigInt& m) {
    if (m.cmp(BigInt::fromU64(0)) == 0) throw std::invalid_argument("Division by zero");
    if (a.cmp(m) < 0) return a;  // If a < m, result = a

    BigInt remainder = a;  // Remainder

    // Sequentially subtract powers of two times modulus
    while (remainder.cmp(m) >= 0) {
        BigInt temp = m;
        size_t shift = 0;

        // Find maximum power of two that can be subtracted
        while (remainder.cmp(temp) >= 0) {
            temp = big_lshift(temp, 1);  // Multiply by 2
            shift++;
        }

        // Go back one step
        if (shift > 0) {
            temp = big_rshift(temp, 1);
            shift--;
        }

        // Subtract the found value
        remainder = internal_sub(remainder, temp);
    }

    return remainder;
}

// Modular exponentiation (square-and-multiply algorithm)
BigInt BigInt::modExp(const BigInt& base, const BigInt& exp, const BigInt& mod) {
    if (mod.cmp(BigInt::fromU64(0)) == 0) throw std::invalid_argument("Modulus cannot be zero");
    if (mod.cmp(BigInt::fromU64(1)) == 0) return BigInt::fromU64(0);

    const BigIntAccess& acc_exp = GET_CONST_ACCESS(exp);
    if (acc_exp.length_ == 0) return BigInt::fromU64(1);

    BigInt result = BigInt::fromU64(1);
    BigInt base_val = BigInt::modNaive(base, mod); // base mod mod
    BigInt exp_val = exp;

    // Square-and-multiply algorithm
    while (exp_val.cmp(BigInt::fromU64(0)) > 0) {
        // If least significant bit of exponent = 1
        if (!exported_is_even(exp_val)) {
            result = BigInt::modNaive(BigInt::mulNaive(result, base_val), mod);
        }

        // Square the base
        base_val = BigInt::modNaive(BigInt::mulNaive(base_val, base_val), mod);

        // Shift exponent right (divide by 2)
        exp_val = exported_big_rshift(exp_val, 1);
    }

    return result;
}

// Division with remainder
BigInt BigInt::divmod(const BigInt& a, const BigInt& b, BigInt* remainder) {
    if (b.cmp(BigInt::fromU64(0)) == 0) {
        throw std::invalid_argument("Division by zero");
    }

    if (a.cmp(b) < 0) {
        if (remainder) *remainder = a;
        return BigInt::fromU64(0);
    }

    BigInt quotient = BigInt::fromU64(0);
    BigInt dividend = a;

    while (dividend.cmp(b) >= 0) {
        BigInt temp = b;
        size_t shift = 0;

        // Find maximum shift
        while (dividend.cmp(temp) >= 0) {
            temp = big_lshift(temp, 1);
            shift++;
            if (shift > 10000) {
                throw std::runtime_error("Too many shifts in division");
            }
        }

        // Go back one step
        if (shift > 0) {
            temp = big_rshift(temp, 1);
            shift--;
        }

        // Subtract
        dividend = internal_sub(dividend, temp);

        // Add to quotient
        BigInt shift_val = BigInt::fromU64(1);
        shift_val = big_lshift(shift_val, shift);
        quotient = internal_add(quotient, shift_val);
    }

    if (remainder) *remainder = dividend;
    return quotient;
}

// =========================================================================
// IMPLEMENTATION OF MontgomeryCtx (MONTGOMERY MULTIPLIER)
// =========================================================================

// Constructor for Montgomery context
MontgomeryCtx::MontgomeryCtx(const BigInt& mod) {
    const BigIntAccess& acc_mod = GET_CONST_ACCESS(mod);

    // Check modulus validity
    if (mod.cmp(BigInt::fromU64(1)) <= 0) {
        throw std::runtime_error("Montgomery modulus must be > 1");
    }
    if ((acc_mod.digits_[0] & 1) == 0) {
        throw std::runtime_error("Montgomery modulus must be odd");
    }

    mod_ = std::make_unique<BigInt>(mod);  // Store modulus
    n_words_ = acc_mod.length_;            // Number of words in modulus

    // Calculate R = 2^(n_words * 32) - power of two greater than modulus
    R_ = std::make_unique<BigInt>(BigInt::fromU64(1));
    *R_ = big_lshift(*R_, n_words_ * WORD_BITS);

    try {
        // Calculate R^{-1} mod N using extended Euclidean algorithm
        R_inv_ = std::make_unique<BigInt>(mod_inverse_binary(*R_, *mod_));
    }
    catch (const std::exception& e) {
        std::cout << "Warning: R_inv calculation failed: " << e.what() << std::endl;
        // Fallback - use 1 (simplified implementation)
        R_inv_ = std::make_unique<BigInt>(BigInt::fromU64(1));
    }

    // Calculate n' = -N^{-1} mod 2^32 (for MonPro algorithm)
    uint32_t N0 = acc_mod.digits_[0];           // Least significant word of modulus
    uint32_t N0_inv = mod_inverse_u32(N0);      // Inverse modulo 2^32
    nprime_ = (uint32_t)(0 - N0_inv);           // Negative inverse
}

// Destructor
MontgomeryCtx::~MontgomeryCtx() = default;

// Convert to Montgomery representation: a_bar = a * R mod N
BigInt MontgomeryCtx::toMont(const BigInt& a) const {
    // a_bar = a * R mod N
    BigInt aR = BigInt::mulNaive(a, *R_);        // Multiply by R
    BigInt result = BigInt::modNaive(aR, *mod_); // Take modulo N
    return result;
}

// Convert from Montgomery representation: a = a_bar * R^{-1} mod N
BigInt MontgomeryCtx::fromMont(const BigInt& a_bar) const {
    // a = a_bar * R^{-1} mod N
    return BigInt::modNaive(BigInt::mulNaive(a_bar, *R_inv_), *mod_);
}

// Montgomery multiplication: (a_bar * b_bar * R^{-1}) mod N
BigInt MontgomeryCtx::mul(const BigInt& a_bar, const BigInt& b_bar) const {
    const BigIntAccess& acc_mod = GET_CONST_ACCESS(*mod_);
    const BigIntAccess& acc_a = GET_CONST_ACCESS(a_bar);
    const BigIntAccess& acc_b = GET_CONST_ACCESS(b_bar);

    size_t len_a = acc_a.length_;
    size_t len_b = acc_b.length_;
    BigInt T(n_words_ * 2 + 1);
    BigIntAccess& acc_T = GET_ACCESS(T);

    // Schoolbook multiplication to get T = a_bar * b_bar
    for (size_t i = 0; i < len_a; ++i) {
        uint64_t carry = 0;
        for (size_t j = 0; j < len_b; ++j) {
            uint64_t product = (uint64_t)acc_a.digits_[i] * acc_b.digits_[j];
            uint64_t sum = product + acc_T.digits_[i + j] + carry;
            acc_T.digits_[i + j] = (uint32_t)(sum & MAX_WORD);
            carry = sum >> WORD_BITS;
        }
        if (carry > 0) {
            acc_T.digits_[i + len_b] = (uint32_t)carry;
        }
    }

    // Montgomery reduction
    for (size_t i = 0; i < n_words_; ++i) {
        // m_i = T[i] * nprime mod 2^32
        uint32_t m_i = (acc_T.digits_[i] * nprime_) & MAX_WORD;
        uint64_t carry = 0;

        // T = T + m_i * N * 2^(32*i)
        for (size_t j = 0; j < n_words_; ++j) {
            uint64_t product = (uint64_t)m_i * acc_mod.digits_[j];
            uint64_t sum = (uint64_t)acc_T.digits_[i + j] + (product & MAX_WORD) + carry;
            acc_T.digits_[i + j] = (uint32_t)(sum & MAX_WORD);
            carry = (product >> WORD_BITS) + (sum >> WORD_BITS);
        }

        // Propagate carry
        for (size_t j = n_words_; carry > 0 && (i + j) < acc_T.length_; ++j) {
            uint64_t sum = (uint64_t)acc_T.digits_[i + j] + carry;
            acc_T.digits_[i + j] = (uint32_t)(sum & MAX_WORD);
            carry = sum >> WORD_BITS;
        }
    }

    // Get result from upper half of T
    BigInt U(n_words_ + 1);
    BigIntAccess& acc_U = GET_ACCESS(U);

    for (size_t i = 0; i <= n_words_; ++i) {
        if (i + n_words_ < acc_T.length_) {
            acc_U.digits_[i] = acc_T.digits_[i + n_words_];
        }
    }
    normalize(U);

    // Final reduction if U >= N
    if (U.cmp(*mod_) >= 0) {
        U = internal_sub(U, *mod_);
    }

    return U;
}

// Montgomery exponentiation
BigInt MontgomeryCtx::exp(const BigInt& base, const BigInt& exp) const {
    const BigIntAccess& acc_exp = GET_CONST_ACCESS(exp);
    if (acc_exp.length_ == 0) return BigInt::fromU64(1);  // base^0 = 1

    BigInt base_mod = BigInt::modNaive(base, *mod_);
    BigInt base_bar = toMont(base_mod);

    BigInt result_bar = toMont(BigInt::fromU64(1));

    size_t bit_length = count_bits(exp);

    for (size_t i = 0; i < bit_length; ++i) {
        if (get_bigint_bit(exp, i)) {
            result_bar = mul(result_bar, base_bar);
        }
        base_bar = mul(base_bar, base_bar);
    }

    return fromMont(result_bar);
}

// =========================================================================
// =========================================================================

BigInt mod_exp(const BigInt& base, const BigInt& exp, const BigInt& mod) {
    return BigInt::modExp(base, exp, mod);
}

std::unique_ptr<MontgomeryCtx> montgomery_init(const BigInt& mod) {
    return std::make_unique<MontgomeryCtx>(mod);
}

BigInt montgomery_exp(const BigInt& base, const BigInt& exp, const MontgomeryCtx& ctx) {
    return ctx.exp(base, exp);
}

BigInt montgomery_mul(const BigInt& a, const BigInt& b, const MontgomeryCtx& ctx) {
    BigInt a_bar = ctx.toMont(a);
    BigInt b_bar = ctx.toMont(b);
    BigInt result_bar = ctx.mul(a_bar, b_bar);

    return ctx.fromMont(result_bar);
}
