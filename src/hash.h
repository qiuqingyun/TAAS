#pragma once
#include "base.h"

// 递归展开函数模板
template <typename... Args>
inline std::string str_bind(const Args &...args)
{
    std::string result;
    // C++17 折叠表达式 (fold expression)
    // 初始化 result 为折叠表达式 (((result + args) + ...) + args)
    ((result += args), ...);
    return result;
}

// 计算输入值的哈希值
inline BIGNUM *BN_hash(std::string input)
{
    BIGNUM *hash = BN_new();
    unsigned char *out = new unsigned char[32];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.length());
    SHA256_Final(out, &sha256);
    BN_bin2bn(out, 32, hash);
    delete[] out;
    return hash;
}