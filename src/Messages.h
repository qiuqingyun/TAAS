#pragma once
#include "base.h"
#include "ElGamal.h"

class User_data
{
public:
    BIGNUM *u, *r, *v;
    // 构造函数
    User_data() {}

    // 深拷贝构造函数
    User_data(User_data *user_data)
    {
        u = BN_dup(user_data->u);
        r = BN_dup(user_data->r);
        if (user_data->v != NULL)
            v = BN_dup(user_data->v);
    }

    // 释放内存
    ~User_data()
    {
        BN_free(u);
        BN_free(r);
        BN_free(v);
    }
};

class User_evidence
{
public:
    EC_POINT *U;
    ElGamal_ciphertext *V;

    // 释放内存
    ~User_evidence()
    {
        EC_POINT_free(U);
        delete V;
    }
};

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

class Message_P1
{
public:
    EC_POINT *P_ = nullptr;
    EC_POINT **P = nullptr;
    BIGNUM *Z_hat = nullptr;

    Message_P1() {}

    // 使用COPY深拷贝构造函数
    Message_P1(EC_GROUP *curve, int user_count, Message_P1 *message)
    {
        P_ = EC_POINT_new(curve);
        EC_POINT_copy(P_, message->P_);
        P = new EC_POINT *[user_count];
        for (int i = 0; i < user_count; i++)
        {
            P[i] = EC_POINT_new(curve);
            EC_POINT_copy(P[i], message->P[i]);
        }
        Z_hat = BN_dup(message->Z_hat);
    }
};

class Message_A2
{
public:
    ElGamal_ciphertext **C = nullptr;
    ElGamal_ciphertext **C_ = nullptr;
    EC_POINT **CA = nullptr;
    EC_POINT **CB = nullptr;
    EC_POINT **CD_ = nullptr;
    EC_POINT **A = nullptr;
    BIGNUM *E = nullptr;
    ElGamal_ciphertext *F = nullptr;
    EC_POINT **Q = nullptr;
    EC_POINT *GS_ = nullptr;
    EC_POINT *GS = nullptr;
    EC_POINT *pkA_ = nullptr;
    BIGNUM *skA_hat = nullptr;

    Message_A2() {}

    // 使用COPY深拷贝构造函数
    Message_A2(EC_GROUP *curve, int user_count_advertiser, int user_count_platform, Message_A2 *message)
    {
        C = new ElGamal_ciphertext *[user_count_platform];
        C_ = new ElGamal_ciphertext *[user_count_platform];
        CA = new EC_POINT *[user_count_platform];
        CB = new EC_POINT *[user_count_platform];
        CD_ = new EC_POINT *[user_count_platform];
        A = new EC_POINT *[user_count_advertiser];
        Q = new EC_POINT *[user_count_platform];
        for (int i = 0; i < user_count_platform; i++)
        {
            C[i] = new ElGamal_ciphertext(curve, message->C[i]);
            C_[i] = new ElGamal_ciphertext(curve, message->C_[i]);
            CA[i] = EC_POINT_new(curve);
            CB[i] = EC_POINT_new(curve);
            CD_[i] = EC_POINT_new(curve);
            Q[i] = EC_POINT_new(curve);
            EC_POINT_copy(CA[i], message->CA[i]);
            EC_POINT_copy(CB[i], message->CB[i]);
            EC_POINT_copy(CD_[i], message->CD_[i]);
            EC_POINT_copy(Q[i], message->Q[i]);
        }
        for (int i = 0; i < user_count_advertiser; i++)
        {
            A[i] = EC_POINT_new(curve);
            EC_POINT_copy(A[i], message->A[i]);
        }
        E = BN_dup(message->E);
        F = new ElGamal_ciphertext(curve, message->F);
        GS_ = EC_POINT_new(curve);
        GS = EC_POINT_new(curve);
        pkA_ = EC_POINT_new(curve);
        skA_hat = BN_dup(message->skA_hat);
        EC_POINT_copy(GS_, message->GS_);
        EC_POINT_copy(GS, message->GS);
        EC_POINT_copy(pkA_, message->pkA_);
    }
};

class Message_P3
{
public:
    EC_POINT **J = nullptr;
    EC_POINT **L = nullptr;
    BIGNUM *k2_hat = nullptr;
    EC_POINT *C2 = nullptr;
    EC_POINT *C2_ = nullptr;
    EC_POINT *C3 = nullptr;
    EC_POINT *C3_ = nullptr;
    BIGNUM *kq_hat = nullptr;
    EC_POINT *Q_ = nullptr;
    EC_POINT *A_ = nullptr;

    Message_P3() {}

    // 使用COPY深拷贝构造函数
    Message_P3(EC_GROUP *curve, int user_count_advertiser, int user_count_platform, Message_P3 *message)
    {
        J = new EC_POINT *[user_count_platform];
        L = new EC_POINT *[user_count_advertiser];
        for (int j = 0; j < user_count_platform; j++)
        {
            J[j] = EC_POINT_new(curve);
            EC_POINT_copy(J[j], message->J[j]);
        }
        for (int i = 0; i < user_count_advertiser; i++)
        {
            L[i] = EC_POINT_new(curve);
            EC_POINT_copy(L[i], message->L[i]);
        }
        k2_hat = BN_dup(message->k2_hat);
        C2 = EC_POINT_new(curve);
        C2_ = EC_POINT_new(curve);
        C3 = EC_POINT_new(curve);
        C3_ = EC_POINT_new(curve);
        kq_hat = BN_dup(message->kq_hat);
        Q_ = EC_POINT_new(curve);
        A_ = EC_POINT_new(curve);
        EC_POINT_copy(C2, message->C2);
        EC_POINT_copy(C2_, message->C2_);
        EC_POINT_copy(C3, message->C3);
        EC_POINT_copy(C3_, message->C3_);
        EC_POINT_copy(Q_, message->Q_);
        EC_POINT_copy(A_, message->A_);
    }
};

class Message_A4
{
public:
    EC_POINT *Sum_D = nullptr;
    BIGNUM *Sum = nullptr;
    EC_POINT *GK = nullptr;
    EC_POINT *GK_ = nullptr;
    EC_POINT *pkA__ = nullptr;
    BIGNUM *skA_hat_ = nullptr;

    Message_A4() {}

    // 使用COPY深拷贝构造函数
    Message_A4(EC_GROUP *curve, Message_A4 *message)
    {
        Sum_D = EC_POINT_new(curve);
        Sum = BN_dup(message->Sum);
        GK = EC_POINT_new(curve);
        GK_ = EC_POINT_new(curve);
        pkA__ = EC_POINT_new(curve);
        skA_hat_ = BN_dup(message->skA_hat_);
        EC_POINT_copy(Sum_D, message->Sum_D);
        EC_POINT_copy(GK, message->GK);
        EC_POINT_copy(GK_, message->GK_);
        EC_POINT_copy(pkA__, message->pkA__);
    }
};