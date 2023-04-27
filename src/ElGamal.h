// ElGamal加密相关操作
#pragma once
#include "base.h"
#include "ec.h"

class ElGamal_ciphertext
{
public:
    EC_POINT *C1;
    EC_POINT *C2;

    // 构造函数
    ElGamal_ciphertext() {}

    // 深拷贝构造函数
    ElGamal_ciphertext(EC_GROUP *curve, ElGamal_ciphertext *ciphertext)
    {
        C1 = EC_POINT_dup(ciphertext->C1, curve);
        C2 = EC_POINT_dup(ciphertext->C2, curve);
    }

    // 释放内存
    ~ElGamal_ciphertext()
    {
        EC_POINT_free(C1);
        EC_POINT_free(C2);
    }
};

// ElGamal同态加法
ElGamal_ciphertext *ElGamal_add(EC_GROUP *curve, ElGamal_ciphertext *ciphertext1, ElGamal_ciphertext *ciphertext2, BN_CTX *ctx)
{
    ElGamal_ciphertext *answer = new ElGamal_ciphertext();
    answer->C1 = EC_POINT_new(curve);
    answer->C2 = EC_POINT_new(curve);
    EC_POINT_add(curve, answer->C1, ciphertext1->C1, ciphertext2->C1, ctx);
    EC_POINT_add(curve, answer->C2, ciphertext1->C2, ciphertext2->C2, ctx);
    return answer;
}

// // 生成密钥对
// void ElGamal_keygen(EC_GROUP *curve, W1 *w1, EC_POINT **pk, BIGNUM **sk, BN_CTX *ctx)
// {
//     // 生成私钥
//     *sk = BN_new();
//     BN_rand(*sk, 256, -1, 0);
//     // 生成公钥pk=sk*base
//     *pk = EC_POINT_new(curve);
//     EC_POINT_mul(curve, *pk, NULL, w1->get_Ha(), *sk, ctx);
// }

// // 加密函数
// ElGamal_ciphertext *ElGamal_encrypt(EC_GROUP *curve, W1 *w1, EC_POINT *pk, BIGNUM *plaintext, BN_CTX *ctx)
// {
//     ElGamal_ciphertext *ciphertext = new ElGamal_ciphertext;
//     ciphertext->C1 = EC_POINT_new(curve);
//     ciphertext->C2 = EC_POINT_new(curve);
//     // 生成随机数r
//     BIGNUM *r = BN_new();
//     BN_rand(r, 256, -1, 0);
//     // 计算C1 = plaintext*Ga + r*pk
//     EC_POINT *temp1 = EC_POINT_new(curve);
//     EC_POINT *temp2 = EC_POINT_new(curve);
//     EC_POINT_mul(curve, temp1, NULL, w1->get_Ga(), plaintext, ctx);
//     EC_POINT_mul(curve, temp2, NULL, pk, r, ctx);
//     EC_POINT_add(curve, ciphertext->C1, temp1, temp2, ctx);
//     // 计算C2 = r*Ha
//     EC_POINT_mul(curve, ciphertext->C2, NULL, w1->get_Ha(), r, ctx);
//     // 释放内存
//     BN_free(r);
//     EC_POINT_free(temp1);
//     EC_POINT_free(temp2);
//     return ciphertext;
// }

// // 解密函数
// BIGNUM *ElGamal_decrypt(EC_GROUP *curve, W1 *w1, BIGNUM *sk, ElGamal_ciphertext *ciphertext, BN_CTX *ctx)
// {
//     // 计算m = (C1 - sk*C2)/Ga
//     BIGNUM *plaintext = BN_new();
//     EC_POINT *temp1 = EC_POINT_new(curve);
//     EC_POINT *temp2 = EC_POINT_new(curve);
//     // 计算sk*C2
//     EC_POINT_mul(curve, temp1, NULL, ciphertext->C2, sk, ctx);
//     // 计算C1 - sk*C2
//     EC_POINT_sub(curve, temp2, ciphertext->C1, temp1, ctx);
//     // 计算Ga^(-1)
//     EC_POINT *Ga_invert = EC_POINT_new(curve);
//     EC_POINT_copy(Ga_invert, w1->get_Ga());
//     EC_POINT_invert(curve, Ga_invert, ctx);
//     // 计算m = (C1 - sk*C2)*Ga^(-1)
//     EC_POINT_mul(curve, temp2, NULL, temp2, Ga_invert, ctx);

//     EC_POINT_mul(curve, temp1, NULL, w1->get_Ga(), sk, ctx);
//     EC_POINT_sub(curve, temp2, temp2, temp1, ctx);
//     EC_POINT_invert(curve, temp1, w1->get_Ga(), ctx);
//     EC_POINT_mul(curve, temp2, NULL, temp2, temp1, ctx);
//     EC_POINT_get_affine_coordinates_GFp(curve, temp2, plaintext, NULL, ctx);

//     // 释放内存

//     return plaintext;
// }
