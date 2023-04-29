#pragma once
#include "base.h"
#include "ec.h"
#include "hash.h"
#include "Messages.h"

class Platform
{
    W1 *w1;
    int user_count_advertiser;
    int user_count_platform;
    // 广告主拥有的用户身份标识
    BIGNUM **user_id_platform = nullptr;
    // 证明Proof
    Proof *proof = nullptr;
    Message_P1 *message_p1 = nullptr;
    Message_P3 *message_p3 = nullptr;

    // 共享变量
    BIGNUM *k2 = BN_rand(256);
    BIGNUM *k3 = BN_rand(256);

public:
    // 构造函数
    Platform(W1 *w1, int user_count_advertiser, int user_count_platform, BIGNUM **user_id_platform) : w1(w1), user_count_advertiser(user_count_advertiser), user_count_platform(user_count_platform), user_id_platform(user_id_platform) {}

    // 析构函数
    ~Platform()
    {
        delete proof;
        delete message_p1;
        delete message_p3;
        BN_free(k2);
        BN_free(k3);
    }

    // 验证证明
    bool proof_verify(Proof *proof, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        this->proof = new Proof(w1->get_curve(), proof);

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
        std::string combined = str_bind(w1->to_string(ctx), p0.to_string(ctx));
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
        for (int i = 0; i < user_count_advertiser; i++)
        {
            // 临时变量
            BN_CTX *temp_ctx = BN_CTX_new();
            EC_POINT *temp_right3 = EC_POINT_new(w1->get_curve());
            EC_POINT *temp_right4 = EC_POINT_new(w1->get_curve());
            // 设置公开参数组Pi
            Pi pi(w1->get_curve(), proof->A[i], proof->D[i]);
            // 计算哈希值 Si = hash(i||W1||Pi)
            std::string combined = str_bind(std::to_string(i), w1->to_string(temp_ctx), pi.to_string(temp_ctx));
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

    void round_P1(BN_CTX *ctx)
    {
        message_p1 = new Message_P1();
        message_p1->user_count_platform = user_count_platform;
        // 选择随机数Z'
        BIGNUM *Z_ = BN_rand(256);
        // 计算 P'=Z'*G2
        message_p1->P_ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), message_p1->P_, NULL, w1->get_G2(), Z_, ctx);
        // 设置 Z_hat=Z'
        message_p1->Z_hat = BN_dup(Z_);
        // 保存向量P
        message_p1->P = new EC_POINT *[user_count_platform];
        for (int j = 0; j < user_count_platform; ++j)
        {
            // 计算 Pj=k3*Wj*G2
            message_p1->P[j] = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), message_p1->P[j], NULL, w1->get_G2(), k3, ctx);
            EC_POINT_mul(w1->get_curve(), message_p1->P[j], NULL, message_p1->P[j], user_id_platform[j], ctx);
            // 计算哈希值 t_j=H(j||W1||P')
            char *temp_P_ = EC_POINT_point2hex(w1->get_curve(), message_p1->P_, POINT_CONVERSION_COMPRESSED, ctx);
            std::string combined = str_bind(
                std::to_string(j),
                w1->to_string(ctx),
                temp_P_);
            OPENSSL_free(temp_P_);
            BIGNUM *t_j = BN_hash(combined);
            // 计算 Z_hat = Z_hat + tj*k3*Wj
            BIGNUM *temp = BN_new();
            BN_mul(temp, t_j, k3, ctx);
            BN_mul(temp, temp, user_id_platform[j], ctx);
            BN_add(message_p1->Z_hat, message_p1->Z_hat, temp);
            BN_free(temp);
            BN_free(t_j);
        }
        // 释放内存
        BN_free(Z_);
    }

    int round_P3(Message_A2 *message, BN_CTX *ctx)
    {
        message_p3 = new Message_P3();
        message_p3->user_count_advertiser = user_count_advertiser;
        message_p3->user_count_platform = user_count_platform;
        // 验证上一轮的计算
        {
            // 计算哈希值x,y,z和ts
            char *temp_CA = EC_POINT_point2hex(w1->get_curve(), message->CA[0], POINT_CONVERSION_COMPRESSED, ctx);
            std::string combined = str_bind(
                w1->to_string(ctx),
                temp_CA);
            OPENSSL_free(temp_CA);
            BIGNUM *x = BN_hash(combined);
            char *temp_CB = EC_POINT_point2hex(w1->get_curve(), message->CB[0], POINT_CONVERSION_COMPRESSED, ctx);
            combined = str_bind(
                "1",
                w1->to_string(ctx),
                temp_CB);
            BIGNUM *y = BN_hash(combined);
            combined = str_bind(
                "2",
                w1->to_string(ctx),
                temp_CB);
            OPENSSL_free(temp_CB);
            BIGNUM *z = BN_hash(combined);
            char *temp_GS = EC_POINT_point2hex(w1->get_curve(), message->GS_, POINT_CONVERSION_COMPRESSED, ctx);
            char *temp_pkA = EC_POINT_point2hex(w1->get_curve(), message->pkA_, POINT_CONVERSION_COMPRESSED, ctx);
            combined = str_bind(
                w1->to_string(ctx),
                temp_GS,
                temp_pkA);
            OPENSSL_free(temp_GS);
            OPENSSL_free(temp_pkA);
            BIGNUM *ts = BN_hash(combined);
            // 保存向量CD
            EC_POINT **CD = new EC_POINT *[user_count_platform];
            for (int j = 0; j < user_count_platform; ++j)
            {
                // 计算 CDj = y*CAj + CBj - z*G2
                CD[j] = EC_POINT_new(w1->get_curve());
                EC_POINT *temp = EC_POINT_new(w1->get_curve());
                EC_POINT_mul(w1->get_curve(), temp, NULL, message->CA[j], y, ctx); // y*CAj
                EC_POINT_add(w1->get_curve(), CD[j], temp, message->CB[j], ctx);   // y*CAj + CBj
                EC_POINT_mul(w1->get_curve(), temp, NULL, w1->get_G2(), z, ctx);
                EC_POINT_invert(w1->get_curve(), temp, ctx); // -z*G2
                EC_POINT_add(w1->get_curve(), CD[j], CD[j], temp, ctx);
                EC_POINT_free(temp);
            }
            // 验证向量CD_和CD中的元素是否相等
            for (int j = 0; j < user_count_platform; ++j)
            {
                // 比较CD_[j]和CD[j]
                if (EC_POINT_cmp(w1->get_curve(), message->CD_[j], CD[j], ctx) != 0)
                {
                    std::cout << "failed: P3" << std::endl;
                    std::cout << "CD_[" << j << "] != CD[" << j << "]" << std::endl;
                    return 1;
                }
            }
            // 验证 E = (x^1 + y*1 - z) * (x^2 + y*2 - z) * ... * (x^m + y*m - z)
            BIGNUM *E_ = BN_new();
            BN_one(E_);
            for (int j = 0; j < user_count_platform; ++j)
            {
                // 将j转换为BIGNUM
                BIGNUM *j_bn = BN_new();
                BN_set_word(j_bn, j + 1);
                BIGNUM *temp1 = BN_new();
                BIGNUM *temp2 = BN_new();
                BN_mod_exp(temp1, x, j_bn, w1->get_order(), ctx);      // x^j
                BN_mod_mul(temp2, y, j_bn, w1->get_order(), ctx);      // y*j
                BN_mod_add(temp1, temp1, temp2, w1->get_order(), ctx); // x^j + y*j
                BN_mod_sub(temp2, temp1, z, w1->get_order(), ctx);     // x^j + y*j - z
                BN_mod_mul(E_, E_, temp2, w1->get_order(), ctx);       // E' *= x^j + y*j - z
                // 释放内存
                BN_free(j_bn);
                BN_free(temp1);
                BN_free(temp2);
            }
            // 比较 E 和 E_
            if (BN_cmp(message->E, E_) != 0)
            {
                std::cout << "failed: P3" << std::endl;
                std::cout << "E != E_" << std::endl;
                return 1;
            }
            // 验证 F = C1*x^1 + C2*x^2 + ... + Cm*x^m
            // 赋值 F' = C1*x^1
            ElGamal_ciphertext *F_ = new ElGamal_ciphertext(w1->get_curve(), message->C[0]->C1, message->C[0]->C2);
            ElGamal_mul(w1->get_curve(), F_, F_, x, ctx);
            for (int j = 1; j < user_count_platform; ++j)
            {
                // 计算 Cj*x^j
                // 将j转换为BIGNUM
                BIGNUM *j_bn = BN_new();
                BN_set_word(j_bn, j + 1);
                // 计算 x^j
                BIGNUM *temp = BN_new();
                BN_mod_exp(temp, x, j_bn, w1->get_order(), ctx);
                // 计算 Cj*x^j
                ElGamal_ciphertext *temp_c = new ElGamal_ciphertext();
                ElGamal_mul(w1->get_curve(), temp_c, message->C[j], temp, ctx);
                // 计算 F' += Cj*x^j
                ElGamal_add(w1->get_curve(), F_, F_, temp_c, ctx);
                // 释放内存
                BN_free(j_bn);
                BN_free(temp);
                delete temp_c;
            }
            // 比较 F 和 F_
            if (EC_POINT_cmp(w1->get_curve(), message->F->C1, F_->C1, ctx) != 0 || EC_POINT_cmp(w1->get_curve(), message->F->C2, F_->C2, ctx) != 0)
            {
                std::cout << "failed: P3" << std::endl;
                std::cout << "F != F_" << std::endl;
                return 1;
            }
            // 验证 skA_hat*G2 = ts*GS + GS'
            EC_POINT *left = EC_POINT_new(w1->get_curve());
            EC_POINT *right = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), left, NULL, w1->get_G2(), message->skA_hat, ctx); // skA_hat*G2
            EC_POINT_mul(w1->get_curve(), right, NULL, message->GS, ts, ctx);               // ts*GS
            EC_POINT_add(w1->get_curve(), right, right, message->GS_, ctx);                 // ts*GS + GS'
            // 比较 left 和 right
            if (EC_POINT_cmp(w1->get_curve(), left, right, ctx) != 0)
            {
                std::cout << "failed: P3" << std::endl;
                std::cout << "skA_hat*G2 != ts*GS + GS'" << std::endl;
                return 1;
            }
            // 验证 skA_hat*Ha = ts*pkA + pkA'
            EC_POINT_mul(w1->get_curve(), left, NULL, w1->get_Ha(), message->skA_hat, ctx); // skA_hat*Ha
            EC_POINT_mul(w1->get_curve(), right, NULL, w1->get_pkA(), ts, ctx);             // ts*pkA
            EC_POINT_add(w1->get_curve(), right, right, message->pkA_, ctx);                // ts*pkA + pkA'
            // 比较 left 和 right
            if (EC_POINT_cmp(w1->get_curve(), left, right, ctx) != 0)
            {
                std::cout << "failed: P3" << std::endl;
                std::cout << "skA_hat*Ha != ts*pkA + pkA'" << std::endl;
                return 1;
            }
            // 释放内存
            EC_POINT_free(left);
            EC_POINT_free(right);
            delete F_;
            BN_free(x);
            BN_free(y);
            BN_free(z);
            BN_free(ts);
            BN_free(E_);
            // 释放CD
            for (int j = 0; j < user_count_platform; ++j)
            {
                EC_POINT_free(CD[j]);
            }
            delete[] CD;
        }
        // 选择随机数 k2'，kq'
        BIGNUM *k2_ = BN_rand(256);
        BIGNUM *kq_ = BN_rand(256);
        // 选择m个随机数 {b1,b2,...,bm}
        BIGNUM **b = new BIGNUM *[user_count_platform];
        for (int j = 0; j < user_count_platform; ++j)
        {
            b[j] = BN_rand(256);
        }
        // 选择n个随机数{c1,c2,...,cn}
        BIGNUM **c = new BIGNUM *[user_count_advertiser];
        for (int j = 0; j < user_count_advertiser; ++j)
        {
            c[j] = BN_rand(256);
        }
        // 设置 Q'=0
        message_p3->Q_ = EC_POINT_new(w1->get_curve());
        // 保存向量J
        message_p3->J = new EC_POINT *[user_count_platform];
        for (int j = 0; j < user_count_platform; ++j)
        {
            // 计算 Jj = k2*Qj
            message_p3->J[j] = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), message_p3->J[j], NULL, message->Q[j], k2, ctx);
            // 计算 Q' = Q' + bj*Qj
            EC_POINT *temp = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), temp, NULL, message->Q[j], b[j], ctx);
            EC_POINT_add(w1->get_curve(), message_p3->Q_, message_p3->Q_, temp, ctx);
            // 释放内存
            EC_POINT_free(temp);
        }
        // 计算 C2 = k2*Q'
        message_p3->C2 = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), message_p3->C2, NULL, message_p3->Q_, k2, ctx);
        // 计算 C2' = k2'*Q'
        message_p3->C2_ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), message_p3->C2_, NULL, message_p3->Q_, k2_, ctx);
        // 计算哈希值 tq = H(W_1||C2')
        char *temp_C2_ = EC_POINT_point2hex(w1->get_curve(), message_p3->C2_, POINT_CONVERSION_COMPRESSED, ctx);
        std::string combine = str_bind(
            w1->to_string(ctx),
            temp_C2_);
        OPENSSL_free(temp_C2_);
        BIGNUM *tq = BN_hash(combine);
        // 计算 k2_hat = tq*k2 + k2'
        message_p3->k2_hat = BN_new();
        BN_mod_mul(message_p3->k2_hat, tq, k2, w1->get_order(), ctx);
        BN_mod_add(message_p3->k2_hat, message_p3->k2_hat, k2_, w1->get_order(), ctx);
        // 设置 A'=0
        message_p3->A_ = EC_POINT_new(w1->get_curve());
        // 保存向量L
        message_p3->L = new EC_POINT *[user_count_advertiser];
        for (int i = 0; i < user_count_advertiser; ++i)
        {
            // 计算 A' = A' + ci*Ai
            EC_POINT *temp = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), temp, NULL, message->A[i], c[i], ctx);
            EC_POINT_add(w1->get_curve(), message_p3->A_, message_p3->A_, temp, ctx);
            // 计算 Li = k3*k2*Ai
            message_p3->L[i] = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), message_p3->L[i], NULL, message->A[i], k3, ctx);
            EC_POINT_mul(w1->get_curve(), message_p3->L[i], NULL, message_p3->L[i], k2, ctx);
            // 释放内存
            EC_POINT_free(temp);
        }
        // 计算 kq = k3*k2
        BIGNUM *kq = BN_new();
        BN_mod_mul(kq, k3, k2, w1->get_order(), ctx);
        // 计算 C3 = kq*A'
        message_p3->C3 = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), message_p3->C3, NULL, message_p3->A_, kq, ctx);
        // 计算 C3' = kq'*A'
        message_p3->C3_ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), message_p3->C3_, NULL, message_p3->A_, kq_, ctx);
        // 计算哈希值 ta = H(W_1||C3')
        char *temp_C3_ = EC_POINT_point2hex(w1->get_curve(), message_p3->C3_, POINT_CONVERSION_COMPRESSED, ctx);
        combine = str_bind(
            w1->to_string(ctx),
            temp_C3_);
        OPENSSL_free(temp_C3_);
        BIGNUM *ta = BN_hash(combine);
        // 计算 kq_hat = ta*kq + kq'
        message_p3->kq_hat = BN_new();
        BN_mod_mul(message_p3->kq_hat, ta, kq, w1->get_order(), ctx);
        BN_mod_add(message_p3->kq_hat, message_p3->kq_hat, kq_, w1->get_order(), ctx);
        // 释放k2_,kq_,b,c,tq,kq,ta的内存
        BN_free(k2_);
        BN_free(kq_);
        for (int j = 0; j < user_count_platform; ++j)
        {
            BN_free(b[j]);
        }
        delete[] b;
        for (int j = 0; j < user_count_advertiser; ++j)
        {
            BN_free(c[j]);
        }
        delete[] c;
        BN_free(tq);
        BN_free(kq);
        BN_free(ta);
        return 0;
    }

    int round_P5(Message_A4 *message, BN_CTX *ctx)
    {
        // 计算哈希值 tb = H(W1||GK'||pkA'')
        char *temp_GK_ = EC_POINT_point2hex(w1->get_curve(), message->GK_, POINT_CONVERSION_COMPRESSED, ctx);
        char *temp_pkA__ = EC_POINT_point2hex(w1->get_curve(), message->pkA__, POINT_CONVERSION_COMPRESSED, ctx);
        std::string combine = str_bind(
            w1->to_string(ctx),
            temp_GK_,
            temp_pkA__);
        OPENSSL_free(temp_GK_);
        OPENSSL_free(temp_pkA__);
        BIGNUM *tb = BN_hash(combine);
        // 验证 skA'_hat*Ga = tb*GK + GK'
        EC_POINT *left = EC_POINT_new(w1->get_curve());
        EC_POINT *right = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), left, NULL, w1->get_Ga(), message->skA_hat_, ctx);
        EC_POINT_mul(w1->get_curve(), right, NULL, message->GK, tb, ctx);
        EC_POINT_add(w1->get_curve(), right, right, message->GK_, ctx);
        if (EC_POINT_cmp(w1->get_curve(), left, right, ctx) != 0)
        {
            std::cout << "failed: P5" << std::endl;
            std::cout << "skA_hat_*Ga != tb*GK + GK'" << std::endl;
        }
        // 验证 skA'_hat*Ha = tb*pkA + pkA''
        EC_POINT_mul(w1->get_curve(), left, NULL, w1->get_Ha(), message->skA_hat_, ctx);
        EC_POINT_mul(w1->get_curve(), right, NULL, w1->get_pkA(), tb, ctx);
        EC_POINT_add(w1->get_curve(), right, right, message->pkA__, ctx);
        if (EC_POINT_cmp(w1->get_curve(), left, right, ctx) != 0)
        {
            std::cout << "failed: P5" << std::endl;
            std::cout << "skA_hat_*Ha != tb*pkA + pkA''" << std::endl;
            return 1;
        }
        // 释放内存
        EC_POINT_free(left);
        EC_POINT_free(right);
        BN_free(tb);
        return 0;
    }

    Message_P1 *get_message_p1() { return new Message_P1(w1->get_curve(), message_p1); }
    Message_P3 *get_message_p3() { return new Message_P3(w1->get_curve(), message_p3); }
};