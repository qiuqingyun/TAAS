#pragma once
#include "base.h"
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
    bool compute(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        EC_POINT *left1 = EC_POINT_new(w1->get_curve());
        EC_POINT *right1 = EC_POINT_new(w1->get_curve());
        EC_POINT *left2 = EC_POINT_new(w1->get_curve());
        EC_POINT *right2 = EC_POINT_new(w1->get_curve());
        EC_POINT *left3 = EC_POINT_new(w1->get_curve());
        EC_POINT *right3 = EC_POINT_new(w1->get_curve());
        EC_POINT *left4 = EC_POINT_new(w1->get_curve());
        EC_POINT *right4 = EC_POINT_new(w1->get_curve());

        // 设置公开参数组P0
        P0 p0(w1->get_curve(), proof->W_, proof->C1_);

        // 计算哈希值 S0 = hash(W1||P0)
        std::string combined = bind(w1->to_string(ctx), p0.to_string(ctx));
        BIGNUM *S0 = BN_hash(combined);

        // 验证等式是否成立: k_hat*G1 = S0*W + W'
        EC_POINT_mul(w1->get_curve(), left1, NULL, w1->get_G1(), proof->k_hat, ctx);
        EC_POINT_mul(w1->get_curve(), right1, NULL, proof->W, S0, ctx);
        EC_POINT_add(w1->get_curve(), right1, right1, proof->W_, ctx);

        // 验证等式是否成立: k_hat*U' = S0*C1 + C1'
        EC_POINT_mul(w1->get_curve(), left2, NULL, proof->U_, proof->k_hat, ctx);
        EC_POINT_mul(w1->get_curve(), right2, NULL, proof->C1, S0, ctx);
        EC_POINT_add(w1->get_curve(), right2, right2, proof->C1_, ctx);

        // 验证等式是否成立: x_hat*G2 = A' + S1*A1 + S2*A2 + ... + Sn*An
        EC_POINT_mul(w1->get_curve(), left3, NULL, w1->get_G2(), proof->x_hat, ctx);
        // 将A'赋值给right
        EC_POINT_copy(right3, proof->A_);

        // 验证等式是否成立: x_hat*G0 + y_hat*H0 = D' + S1*D1 + S2*D2 + ... + Sn*Dn
        EC_POINT_mul(w1->get_curve(), left4, NULL, w1->get_G0(), proof->x_hat, ctx);
        EC_POINT_mul(w1->get_curve(), right4, NULL, w1->get_H0(), proof->y_hat, ctx);
        EC_POINT_add(w1->get_curve(), left4, left4, right4, ctx);
        // 将D'赋值给right
        EC_POINT_copy(right4, proof->D_);

// 并行化
#pragma omp parallel for
        for (int i = 0; i < user_count; i++)
        {
            // 临时变量
            BN_CTX *temp_ctx = BN_CTX_new();
            EC_POINT *temp_right3 = EC_POINT_new(w1->get_curve());
            EC_POINT *temp_right4 = EC_POINT_new(w1->get_curve());
            // 设置公开参数组Pi
            Pi pi(w1->get_curve(), proof->A[i], proof->D[i]);
            // 计算哈希值 Si = hash(i||W1||Pi)
            std::string combined = bind(std::to_string(i), w1->to_string(temp_ctx), pi.to_string(temp_ctx));
            BIGNUM *Si = BN_hash(combined);
            // 计算right3
            EC_POINT_mul(w1->get_curve(), temp_right3, NULL, proof->A[i], Si, temp_ctx);
            // 计算right4
            EC_POINT_mul(w1->get_curve(), temp_right4, NULL, proof->D[i], Si, temp_ctx);
            // 累加right3和right4
            // 多线程加锁
#pragma omp critical
            {
                EC_POINT_add(w1->get_curve(), right3, right3, temp_right3, temp_ctx);
                EC_POINT_add(w1->get_curve(), right4, right4, temp_right4, temp_ctx);
            }
            // 释放内存
            BN_CTX_free(temp_ctx);
            EC_POINT_free(temp_right3);
            EC_POINT_free(temp_right4);
            BN_free(Si);
        }

        // 比较，若有一个不相等则返回错误码
        if (EC_POINT_cmp(w1->get_curve(), left1, right1, ctx) != 0 || EC_POINT_cmp(w1->get_curve(), left2, right2, ctx) != 0 || EC_POINT_cmp(w1->get_curve(), left3, right3, ctx) != 0 || EC_POINT_cmp(w1->get_curve(), left4, right4, ctx) != 0)
        {
            // 打印出错的比较编号
            if (EC_POINT_cmp(w1->get_curve(), left1, right1, ctx) != 0)
            {
                std::cout << "Error 1" << std::endl;
            }
            if (EC_POINT_cmp(w1->get_curve(), left2, right2, ctx) != 0)
            {
                std::cout << "Error 2" << std::endl;
            }
            if (EC_POINT_cmp(w1->get_curve(), left3, right3, ctx) != 0)
            {
                std::cout << "Error 3" << std::endl;
            }
            if (EC_POINT_cmp(w1->get_curve(), left4, right4, ctx) != 0)
            {
                std::cout << "Error 4" << std::endl;
            }
            // 释放内存
            BN_CTX_end(ctx);
            BN_free(S0);
            EC_POINT_free(left1);
            EC_POINT_free(right1);
            EC_POINT_free(left2);
            EC_POINT_free(right2);
            EC_POINT_free(left3);
            EC_POINT_free(right3);
            EC_POINT_free(left4);
            EC_POINT_free(right4);
            return false;
        }
        // 释放内存
        BN_CTX_end(ctx);
        BN_free(S0);
        EC_POINT_free(left1);
        EC_POINT_free(right1);
        EC_POINT_free(left2);
        EC_POINT_free(right2);
        EC_POINT_free(left3);
        EC_POINT_free(right3);
        EC_POINT_free(left4);
        EC_POINT_free(right4);
        return true;
    }
};