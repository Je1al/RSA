#ifndef BIGMATH_HPP
#define BIGMATH_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <memory>
#include <vector>

class BigInt
{
public:

    BigInt(size_t words = 0); 

   
    explicit BigInt(const std::string& hexstr); 

    static BigInt fromDec(const std::string& decstr);

    static BigInt fromU64(uint64_t v);             

    BigInt(const BigInt& other);                   
    BigInt& operator=(const BigInt& other);

    ~BigInt();

    std::string toHex() const; 

    uint64_t toU64OrDie() const;                  

    int cmp(const BigInt& other) const;            
    bool operator==(const BigInt& other) const;
    bool operator!=(const BigInt& other) const;

    static BigInt mulNaive(const BigInt& a, const BigInt& b);
    static BigInt modNaive(const BigInt& a, const BigInt& m);
    static BigInt modExp(const BigInt& base, const BigInt& exp, const BigInt& mod);
    static BigInt divmod(const BigInt& a, const BigInt& b, BigInt* remainder);

    // Number of significant bits / bytes (0 for the value 0).
    size_t bitLength() const;
    size_t byteLength() const;

    // Big-endian octet-string conversions (RFC 8017: I2OSP / OS2IP).
    // toBytesBE(length) left-pads with zeros to exactly `length` bytes and throws
    // std::overflow_error if the integer does not fit.
    std::vector<uint8_t> toBytesBE(size_t length) const;
    std::vector<uint8_t> toBytesBE() const;  // minimal length
    static BigInt fromBytesBE(const uint8_t* data, size_t len);
    static BigInt fromBytesBE(const std::vector<uint8_t>& data);

private:

    uint32_t* digits_;  


    size_t length_;  

    int sign_;             
};


class MontgomeryCtx
{
public:

    explicit MontgomeryCtx(const BigInt& mod);    
    ~MontgomeryCtx();

    // a_bar = a * R mod N
    BigInt toMont(const BigInt& a) const; 

    // a = a_bar * R^{-1} mod N
    BigInt fromMont(const BigInt& a_bar) const;   

    // r = a*b*R^{-1} mod N
    BigInt mul(const BigInt& a, const BigInt& b) const;  

    // r = base^exp mod N
    BigInt exp(const BigInt& base, const BigInt& exp) const; 

private:

    // N
    std::unique_ptr<BigInt> mod_; 

    // R
    std::unique_ptr<BigInt> R_;

    // R^2 mod N (lets toMont use a Montgomery multiply instead of a division)
    std::unique_ptr<BigInt> R2_;

    // -N^{-1} mod base
    uint32_t nprime_;
    size_t n_words_;
};

#endif // BIGMATH_HPP
