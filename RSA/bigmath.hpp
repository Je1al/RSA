#ifndef BIGMATH_HPP
#define BIGMATH_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <memory>

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

    // R^{-1} mod N
    std::unique_ptr<BigInt> R_inv_;    

    // -N^{-1} mod base
    uint32_t nprime_;                  
    size_t n_words_;
};

#endif // BIGMATH_HPP
