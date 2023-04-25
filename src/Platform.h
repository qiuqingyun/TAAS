#pragma once
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include "ec.h"
#include "hash.h"
#include "Advertiser.h"

class Platform
{
    W1 *w1;
    int user_count;
    // 证明Proof
    Proof *proof;

public:
    // 构造函数
    Platform(W1 *w1, int user_count, Proof *proof) : w1(w1), user_count(user_count)
    {
        this->proof = new Proof(w1->get_curve(), proof);
    }

    // 析构函数
    ~Platform()
    {
        delete proof;
    }

    // 验证证明
    int compute(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        EC_POINT *left = EC_POINT_new(w1->get_curve());
        EC_POINT *right = EC_POINT_new(w1->get_curve());

        // 设置公开参数组P0
        P0 p0(w1->get_curve(), proof->W_, proof->C1_);

        // 计算哈希值 S0 = hash(W1||P0)
        std::string combined = bind(w1->to_string(ctx), p0.to_string(ctx));
        BIGNUM *S0 = BN_hash(combined);

        // 验证等式是否成立: k_hat*G1 = S0*W + W'
        EC_POINT_mul(w1->get_curve(), left, NULL, w1->get_G1(), proof->k_hat, ctx);
        EC_POINT_mul(w1->get_curve(), right, NULL, proof->W, S0, ctx);
        EC_POINT_add(w1->get_curve(), right, right, proof->W_, ctx);
        if (EC_POINT_cmp(w1->get_curve(), left, right, ctx) != 0)
        {
            // std::cout << "fail #1" << std::endl;
            return 1;
        }

        // 验证等式是否成立: k_hat*U' = S0*C1 + C1'
        EC_POINT_mul(w1->get_curve(), left, NULL, proof->U_, proof->k_hat, ctx);
        EC_POINT_mul(w1->get_curve(), right, NULL, proof->C1, S0, ctx);
        EC_POINT_add(w1->get_curve(), right, right, proof->C1_, ctx);
        if (EC_POINT_cmp(w1->get_curve(), left, right, ctx) != 0)
        {
            // std::cout << "fail #2" << std::endl;
            return 2;
        }

        // 验证等式是否成立: x_hat*G2 = A' + S1*A1 + S2*A2 + ... + Sn*An
        EC_POINT_mul(w1->get_curve(), left, NULL, w1->get_G2(), proof->x_hat, ctx);
        // 将A'赋值给right
        EC_POINT_copy(right, proof->A_);
        EC_POINT *temp = EC_POINT_new(w1->get_curve());
        for (int i = 0; i < user_count; i++)
        {
            // 设置公开参数组Pi
            Pi pi(w1->get_curve(), proof->A[i], proof->D[i]);
            // 计算哈希值 Si = hash(i||W1||Pi)
            std::string combined = bind(std::to_string(i), w1->to_string(ctx), pi.to_string(ctx));
            BIGNUM *Si = BN_hash(combined);
            // 累加
            EC_POINT_mul(w1->get_curve(), temp, NULL, proof->A[i], Si, ctx);
            EC_POINT_add(w1->get_curve(), right, right, temp, ctx);
            BN_free(Si);
        }
        if (EC_POINT_cmp(w1->get_curve(), left, right, ctx) != 0)
        {
            // std::cout << "fail #3" << std::endl;
            return 3;
        }

        // 验证等式是否成立: x_hat*G0 + y_hat*H0 = D' + S1*D1 + S2*D2 + ... + Sn*Dn
        EC_POINT_mul(w1->get_curve(), left, NULL, w1->get_G0(), proof->x_hat, ctx);
        EC_POINT_mul(w1->get_curve(), right, NULL, w1->get_H0(), proof->y_hat, ctx);
        EC_POINT_add(w1->get_curve(), left, left, right, ctx);
        // 将D'赋值给right
        EC_POINT_copy(right, proof->D_);
        for (int i = 0; i < user_count; i++)
        {
            // 设置公开参数组Pi
            Pi pi(w1->get_curve(), proof->A[i], proof->D[i]);
            // 计算哈希值 Si = hash(i||W1||Pi)
            std::string combined = bind(std::to_string(i), w1->to_string(ctx), pi.to_string(ctx));
            BIGNUM *Si = BN_hash(combined);
            // 累加
            EC_POINT_mul(w1->get_curve(), temp, NULL, proof->D[i], Si, ctx);
            EC_POINT_add(w1->get_curve(), right, right, temp, ctx);
            BN_free(Si);
        }
        if (EC_POINT_cmp(w1->get_curve(), left, right, ctx) != 0)
        {
            // std::cout << "fail #4" << std::endl;
            return 4;
        }

        // 输出验证结果
        // std::cout << "pass" << std::endl;
        BN_CTX_end(ctx);
        // 释放内存
        BN_free(S0);
        EC_POINT_free(left);
        EC_POINT_free(right);
        EC_POINT_free(temp);
        return 0;
    }
};