#pragma once
#include <sstream>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include "ec.h"
#include "hash.h"

class Proof
{
public:
    int user_count;
    EC_POINT *W, *W_, *C1, *C1_, *U_, *A_, *D_, **U, **A, **D;
    BIGNUM *k_hat, *x_hat, *y_hat;

    // 构造函数
    Proof() {}

    // 析构函数
    ~Proof()
    {
        EC_POINT_free(W);
        EC_POINT_free(W_);
        EC_POINT_free(C1);
        EC_POINT_free(C1_);
        EC_POINT_free(U_);
        EC_POINT_free(A_);
        EC_POINT_free(D_);
        for (int i = 0; i < user_count; i++)
        {
            EC_POINT_free(U[i]);
            EC_POINT_free(A[i]);
            EC_POINT_free(D[i]);
        }
        delete[] U;
        delete[] A;
        delete[] D;
        BN_free(k_hat);
        BN_free(x_hat);
        BN_free(y_hat);
    }

    // 使用COPY深拷贝构造函数
    Proof(EC_GROUP *curve, Proof *proof)
    {
        user_count = proof->user_count;
        W = EC_POINT_new(curve);
        EC_POINT_copy(W, proof->W);
        W_ = EC_POINT_new(curve);
        EC_POINT_copy(W_, proof->W_);
        C1 = EC_POINT_new(curve);
        EC_POINT_copy(C1, proof->C1);
        C1_ = EC_POINT_new(curve);
        EC_POINT_copy(C1_, proof->C1_);
        U_ = EC_POINT_new(curve);
        EC_POINT_copy(U_, proof->U_);
        A_ = EC_POINT_new(curve);
        EC_POINT_copy(A_, proof->A_);
        D_ = EC_POINT_new(curve);
        EC_POINT_copy(D_, proof->D_);
        U = new EC_POINT *[user_count];
        A = new EC_POINT *[user_count];
        D = new EC_POINT *[user_count];
        for (int i = 0; i < user_count; i++)
        {
            U[i] = EC_POINT_new(curve);
            EC_POINT_copy(U[i], proof->U[i]);
            A[i] = EC_POINT_new(curve);
            EC_POINT_copy(A[i], proof->A[i]);
            D[i] = EC_POINT_new(curve);
            EC_POINT_copy(D[i], proof->D[i]);
        }
        k_hat = BN_dup(proof->k_hat);
        x_hat = BN_dup(proof->x_hat);
        y_hat = BN_dup(proof->y_hat);
    }

    // 获取Proof的字节数
    size_t get_proof_size(int user_count, EC_GROUP *curve, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        size_t size = 0;
        // 计算*W, *W_, *C1, *C1_, *U_, *A_, *D_, **U, **A, **D的字节数
        size += EC_POINT_point2oct(curve, W, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, W_, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, C1, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, C1_, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, U_, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, A_, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, D_, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        for (int i = 0; i < user_count; i++)
        {
            size += EC_POINT_point2oct(curve, U[i], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
            size += EC_POINT_point2oct(curve, A[i], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
            size += EC_POINT_point2oct(curve, D[i], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        }
        // 计算k_hat, x_hat, y_hat的字节数
        size += BN_num_bytes(k_hat);
        size += BN_num_bytes(x_hat);
        size += BN_num_bytes(y_hat);
        BN_CTX_end(ctx);
        return size;
    }

    size_t serializePoint(EC_POINT *input, std::stringstream &ss, EC_GROUP *curve, BN_CTX *ctx)
    {
        size_t size = EC_POINT_point2oct(curve, W, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        unsigned char *buffer = new unsigned char[size];
        EC_POINT_point2oct(curve, input, POINT_CONVERSION_UNCOMPRESSED, buffer, size, ctx);
        ss.write((char *)buffer, size);
        delete[] buffer;
        return size;
    }

    size_t serializeBN(BIGNUM *input, std::stringstream &ss)
    {
        size_t size = BN_num_bytes(input);
        unsigned char *buffer = new unsigned char[size];
        BN_bn2bin(input, buffer);
        ss.write((char *)buffer, size);
        delete[] buffer;
        return size;
    }

    // 序列化Proof
    std::string serialize(int user_count, EC_GROUP *curve, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        std::string output;
        // 序列化*W, *W_, *C1, *C1_, *U_, *A_, *D_, **U, **A, **D

        // 序列化k_hat, x_hat, y_hat

        BN_CTX_end(ctx);
        return output;
    }

    // 反序列化Proof
    void deserialize(std::string input, int user_count, EC_GROUP *curve, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        std::stringstream ss(input);
        // 反序列化*W, *W_, *C1, *C1_, *U_, *A_, *D_, **U, **A, **D

        // 反序列化k_hat, x_hat, y_hat

        BN_CTX_end(ctx);
    }
};

class Advertiser
{
    W1 *w1;
    int user_count;
    BIGNUM *skA, **u, **r;
    EC_POINT *pkA;
    // 证明Proof
    Proof *proof;

public:
    // 构造函数
    Advertiser(W1 *w1, int user_count) : w1(w1), user_count(user_count)
    {
        // 生成随机数skA作为私钥
        skA = BN_rand(256);
        // 计算公钥pkA = skA*Ha
        pkA = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), pkA, NULL, w1->get_Ha(), skA, NULL);
        w1->set_pkA(pkA);
    }

    // 析构函数
    ~Advertiser()
    {
        BN_free(skA);
        EC_POINT_free(pkA);
        for (int i = 0; i < user_count; i++)
        {
            BN_free(u[i]);
            BN_free(r[i]);
        }
        delete[] u;
        delete[] r;
        delete proof;
    }

    // 计算证明
    void compute(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        this->proof = new Proof();
        proof->user_count = user_count;

        // 生成随机数k1，k'，x'和y'
        BIGNUM *k1 = BN_rand(256);
        BIGNUM *k_ = BN_rand(256);
        BIGNUM *x_ = BN_rand(256);
        BIGNUM *y_ = BN_rand(256);

        // 选择 n 个随机数 {a1,a2,...,an}，其中n为用户数量
        BIGNUM **a = new BIGNUM *[user_count];
        for (int i = 0; i < user_count; i++)
        {
            a[i] = BN_rand(256);
        }

        // 计算 W = k1*G1
        proof->W = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), proof->W, NULL, w1->get_G1(), k1, ctx);

        // 计算 Ui = ui*G_0 + ri*H0，其中i的范围是1到n
        proof->U = new EC_POINT *[user_count];
        for (int i = 0; i < user_count; i++)
        {
            proof->U[i] = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), proof->U[i], NULL, w1->get_G0(), u[i], ctx);
            EC_POINT *temp = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), temp, NULL, w1->get_H0(), r[i], ctx);
            EC_POINT_add(w1->get_curve(), proof->U[i], proof->U[i], temp, ctx);
            EC_POINT_free(temp);
        }

        // 计算 Ai = k1*ui*G2，其中i的范围是1到n
        proof->A = new EC_POINT *[user_count];
        for (int i = 0; i < user_count; i++)
        {
            proof->A[i] = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), proof->A[i], NULL, w1->get_G2(), u[i], ctx);
            EC_POINT_mul(w1->get_curve(), proof->A[i], NULL, proof->A[i], k1, ctx);
        }

        // 计算 Di = k1*Ui，其中i的范围是1到n
        proof->D = new EC_POINT *[user_count];
        for (int i = 0; i < user_count; i++)
        {
            proof->D[i] = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), proof->D[i], NULL, proof->U[i], k1, ctx);
        }

        // 计算 U'= a1*U1 + a2*U2 + ... + an*Un
        proof->U_ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), proof->U_, NULL, proof->U[0], a[0], ctx);
        for (int i = 1; i < user_count; i++)
        {
            EC_POINT *temp = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), temp, NULL, proof->U[i], a[i], ctx);
            EC_POINT_add(w1->get_curve(), proof->U_, proof->U_, temp, ctx);
            EC_POINT_free(temp);
        }

        // 计算 C1 = k1*U'
        proof->C1 = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), proof->C1, NULL, proof->U_, k1, ctx);

        // 计算 C1' = k'*U'
        proof->C1_ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), proof->C1_, NULL, proof->U_, k_, ctx);

        // 计算 W' = k'*G1
        proof->W_ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), proof->W_, NULL, w1->get_G1(), k_, ctx);

        // 设置公开参数组P0
        P0 p0(w1->get_curve(), proof->W_, proof->C1_);

        // 计算哈希值 S0 = hash(W1||P0)
        std::string combined = bind(w1->to_string(ctx), p0.to_string(ctx));
        BIGNUM *S0 = BN_hash(combined);

        // 计算 k_hat = S0*k1+k'
        proof->k_hat = BN_new();
        BN_mod_mul(proof->k_hat, S0, k1, w1->get_order(), ctx);
        BN_mod_add(proof->k_hat, proof->k_hat, k_, w1->get_order(), ctx);

        // 计算 A' = x'*G2
        proof->A_ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), proof->A_, NULL, w1->get_G2(), x_, ctx);

        // 计算 D' = x'*G0 + y'*H0
        proof->D_ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), proof->D_, NULL, w1->get_G0(), x_, ctx);
        EC_POINT *temp = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), temp, NULL, w1->get_H0(), y_, ctx);
        EC_POINT_add(w1->get_curve(), proof->D_, proof->D_, temp, ctx);
        EC_POINT_free(temp);

        // 计算 x_hat = x' + S1*k1*u1 + S2*k1*u2 + ... + Sn*k1*un
        proof->x_hat = BN_new();
        BN_copy(proof->x_hat, x_); // 将x'赋值给x_hat
        for (int i = 0; i < user_count; i++)
        {
            // 设置公开参数组Pi
            Pi pi(w1->get_curve(), proof->A[i], proof->D[i]);
            // 计算哈希值 Si = hash(i||W1||Pi)
            std::string combined = bind(std::to_string(i), w1->to_string(ctx), pi.to_string(ctx));
            BIGNUM *Si = BN_hash(combined);
            // 累加
            BIGNUM *temp = BN_new();
            BN_mod_mul(temp, Si, k1, w1->get_order(), ctx);
            BN_mod_mul(temp, temp, u[i], w1->get_order(), ctx);
            BN_mod_add(proof->x_hat, proof->x_hat, temp, w1->get_order(), ctx);
            BN_free(temp);
            BN_free(Si);
        }

        // 计算 y_hat = y' + S1*k1*r1 + S2*k1*r2 + ... + Sn*k1*rn
        proof->y_hat = BN_new();
        BN_copy(proof->y_hat, y_); // 将y'赋值给y_hat
        for (int i = 0; i < user_count; i++)
        {
            // 设置公开参数组Pi
            Pi pi(w1->get_curve(), proof->A[i], proof->D[i]);
            // 计算哈希值 Si = hash(i||W1||Pi)
            std::string combined = bind(std::to_string(i), w1->to_string(ctx), pi.to_string(ctx));
            BIGNUM *Si = BN_hash(combined);
            // 累加
            BIGNUM *temp = BN_new();
            BN_mod_mul(temp, Si, k1, w1->get_order(), ctx);
            BN_mod_mul(temp, temp, r[i], w1->get_order(), ctx);
            BN_mod_add(proof->y_hat, proof->y_hat, temp, w1->get_order(), ctx);
            BN_free(temp);
            BN_free(Si);
        }
        BN_CTX_end(ctx);
        // 释放内存
        BN_free(k1);
        BN_free(k_);
        BN_free(x_);
        BN_free(y_);
        BN_free(S0);
        for (int i = 0; i < user_count; i++)
        {
            BN_free(a[i]);
        }
        delete[] a;
    }

    // set u和r
    void set_user_data(User_data **user_data)
    {
        this->u = new BIGNUM *[user_count];
        this->r = new BIGNUM *[user_count];
        for (int i = 0; i < user_count; i++)
        {
            this->u[i] = BN_new();
            this->r[i] = BN_new();
            BN_copy(this->u[i], user_data[i]->u);
            BN_copy(this->r[i], user_data[i]->r);
        }
    }
    // set user_count
    void set_user_count(int user_count) { this->user_count = user_count; }
    // get proof
    Proof *get_proof() { return proof; }
};