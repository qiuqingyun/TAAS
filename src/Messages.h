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

    // 构造函数
    User_evidence() {}

    // 深拷贝构造函数
    User_evidence(EC_GROUP *curve, EC_POINT *U, ElGamal_ciphertext *V)
    {
        this->U = EC_POINT_new(curve);
        EC_POINT_copy(this->U, U);
        this->V = new ElGamal_ciphertext(curve, V);
    }

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
    size_t get_size(EC_GROUP *curve, BN_CTX *ctx)
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
    int user_count_platform;
    EC_POINT *P_ = nullptr;
    EC_POINT **P = nullptr;
    BIGNUM *Z_hat = nullptr;

    Message_P1() {}

    // 使用COPY深拷贝构造函数
    Message_P1(EC_GROUP *curve, Message_P1 *message)
    {
        user_count_platform = message->user_count_platform;
        P_ = EC_POINT_new(curve);
        EC_POINT_copy(P_, message->P_);
        P = new EC_POINT *[user_count_platform];
        for (int i = 0; i < user_count_platform; i++)
        {
            P[i] = EC_POINT_new(curve);
            EC_POINT_copy(P[i], message->P[i]);
        }
        Z_hat = BN_dup(message->Z_hat);
    }

    // 释放内存
    ~Message_P1()
    {
        if (P_ != nullptr)
        {
            EC_POINT_free(P_);
            P_ = nullptr;
        }
        if (P != nullptr)
        {
            for (int i = 0; i < user_count_platform; i++)
            {
                if (P[i] != nullptr)
                {
                    EC_POINT_free(P[i]);
                    P[i] = nullptr;
                }
            }
            delete[] P;
            P = nullptr;
        }
        if (Z_hat != nullptr)
        {
            BN_free(Z_hat);
            Z_hat = nullptr;
        }
    }

    // 获取字节数
    size_t get_size(EC_GROUP *curve, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        size_t size = 0;
        size += EC_POINT_point2oct(curve, P_, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        for (int i = 0; i < user_count_platform; i++)
        {
            size += EC_POINT_point2oct(curve, P[i], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        }
        size += BN_num_bytes(Z_hat);
        BN_CTX_end(ctx);
        return size;
    }
};

class Message_A2
{
public:
    int user_count_advertiser;
    int user_count_platform;
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
    Message_A2(EC_GROUP *curve, Message_A2 *message)
    {
        user_count_advertiser = message->user_count_advertiser;
        user_count_platform = message->user_count_platform;
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

    // 释放内存
    ~Message_A2()
    {
        if (C != nullptr)
        {
            for (int i = 0; i < user_count_platform; i++)
            {
                if (C[i] != nullptr)
                {
                    delete C[i];
                    C[i] = nullptr;
                }
            }
            delete[] C;
            C = nullptr;
        }
        if (C_ != nullptr)
        {
            for (int i = 0; i < user_count_platform; i++)
            {
                if (C_[i] != nullptr)
                {
                    delete C_[i];
                    C_[i] = nullptr;
                }
            }
            delete[] C_;
            C_ = nullptr;
        }
        if (CA != nullptr)
        {
            for (int i = 0; i < user_count_platform; i++)
            {
                if (CA[i] != nullptr)
                {
                    EC_POINT_free(CA[i]);
                    CA[i] = nullptr;
                }
            }
            delete[] CA;
            CA = nullptr;
        }
        if (CB != nullptr)
        {
            for (int i = 0; i < user_count_platform; i++)
            {
                if (CB[i] != nullptr)
                {
                    EC_POINT_free(CB[i]);
                    CB[i] = nullptr;
                }
            }
            delete[] CB;
            CB = nullptr;
        }
        if (CD_ != nullptr)
        {
            for (int i = 0; i < user_count_platform; i++)
            {
                if (CD_[i] != nullptr)
                {
                    EC_POINT_free(CD_[i]);
                    CD_[i] = nullptr;
                }
            }
            delete[] CD_;
            CD_ = nullptr;
        }
        if (A != nullptr)
        {
            for (int i = 0; i < user_count_advertiser; i++)
            {
                if (A[i] != nullptr)
                {
                    EC_POINT_free(A[i]);
                    A[i] = nullptr;
                }
            }
            delete[] A;
            A = nullptr;
        }
        if (E != nullptr)
        {
            BN_free(E);
            E = nullptr;
        }
        if (F != nullptr)
        {
            delete F;
            F = nullptr;
        }
        if (Q != nullptr)
        {
            for (int i = 0; i < user_count_platform; i++)
            {
                if (Q[i] != nullptr)
                {
                    EC_POINT_free(Q[i]);
                    Q[i] = nullptr;
                }
            }
            delete[] Q;
            Q = nullptr;
        }
        // 释放GS_,GS,pkA_,skA_hat
        if (GS_ != nullptr)
        {
            EC_POINT_free(GS_);
            GS_ = nullptr;
        }
        if (GS != nullptr)
        {
            EC_POINT_free(GS);
            GS = nullptr;
        }
        if (pkA_ != nullptr)
        {
            EC_POINT_free(pkA_);
            pkA_ = nullptr;
        }
        if (skA_hat != nullptr)
        {
            BN_free(skA_hat);
            skA_hat = nullptr;
        }
    }

    // 获取字节数
    size_t get_size(EC_GROUP *curve, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        size_t size = 0;
        // 计算C,C_,CA,CB,CD_,A,E,F,Q,GS_,GS,pkA_,skA_hat的字节数
        size += EC_POINT_point2oct(curve, GS_, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, GS, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, pkA_, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        size += BN_bn2mpi(skA_hat, NULL);
        size += BN_bn2mpi(E, NULL);
        size += F->get_size(curve, ctx);
        for (int j = 0; j < user_count_platform; j++)
        {
            size += C[j]->get_size(curve, ctx);
            size += C_[j]->get_size(curve, ctx);
            size += EC_POINT_point2oct(curve, CA[j], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
            size += EC_POINT_point2oct(curve, CB[j], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
            size += EC_POINT_point2oct(curve, CD_[j], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
            size += EC_POINT_point2oct(curve, Q[j], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        }
        for (int i = 0; i < user_count_advertiser; i++)
        {
            size += EC_POINT_point2oct(curve, A[i], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        }
        BN_CTX_end(ctx);
        return size;
    }
};

class Message_P3
{
public:
    int user_count_advertiser;
    int user_count_platform;
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
    Message_P3(EC_GROUP *curve, Message_P3 *message)
    {
        user_count_advertiser = message->user_count_advertiser;
        user_count_platform = message->user_count_platform;
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

    // 释放内存
    ~Message_P3()
    {
        if (J != nullptr)
        {
            for (int j = 0; j < user_count_platform; j++)
            {
                if (J[j] != nullptr)
                {
                    EC_POINT_free(J[j]);
                    J[j] = nullptr;
                }
            }
            delete[] J;
            J = nullptr;
        }
        if (L != nullptr)
        {
            for (int i = 0; i < user_count_advertiser; i++)
            {
                if (L[i] != nullptr)
                {
                    EC_POINT_free(L[i]);
                    L[i] = nullptr;
                }
            }
            delete[] L;
            L = nullptr;
        }
        if (k2_hat != nullptr)
        {
            BN_free(k2_hat);
            k2_hat = nullptr;
        }
        if (C2 != nullptr)
        {
            EC_POINT_free(C2);
            C2 = nullptr;
        }
        if (C2_ != nullptr)
        {
            EC_POINT_free(C2_);
            C2_ = nullptr;
        }
        if (C3 != nullptr)
        {
            EC_POINT_free(C3);
            C3 = nullptr;
        }
        if (C3_ != nullptr)
        {
            EC_POINT_free(C3_);
            C3_ = nullptr;
        }
        if (kq_hat != nullptr)
        {
            BN_free(kq_hat);
            kq_hat = nullptr;
        }
        if (Q_ != nullptr)
        {
            EC_POINT_free(Q_);
            Q_ = nullptr;
        }
        if (A_ != nullptr)
        {
            EC_POINT_free(A_);
            A_ = nullptr;
        }
    }

    // 获取字节数
    size_t get_size(EC_GROUP *curve, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        size_t size = 0;
        for (int j = 0; j < user_count_platform; j++)
        {
            size += EC_POINT_point2oct(curve, J[j], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        }
        for (int i = 0; i < user_count_advertiser; i++)
        {
            size += EC_POINT_point2oct(curve, L[i], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        }
        size += BN_bn2mpi(k2_hat, NULL);
        size += EC_POINT_point2oct(curve, C2, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, C2_, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, C3, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, C3_, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        size += BN_bn2mpi(kq_hat, NULL);
        size += EC_POINT_point2oct(curve, Q_, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, A_, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        BN_CTX_end(ctx);
        return size;
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

    // 释放内存
    ~Message_A4()
    {
        if (Sum_D != nullptr)
        {
            EC_POINT_free(Sum_D);
            Sum_D = nullptr;
        }
        if (Sum != nullptr)
        {
            BN_free(Sum);
            Sum = nullptr;
        }
        if (GK != nullptr)
        {
            EC_POINT_free(GK);
            GK = nullptr;
        }
        if (GK_ != nullptr)
        {
            EC_POINT_free(GK_);
            GK_ = nullptr;
        }
        if (pkA__ != nullptr)
        {
            EC_POINT_free(pkA__);
            pkA__ = nullptr;
        }
        if (skA_hat_ != nullptr)
        {
            BN_free(skA_hat_);
            skA_hat_ = nullptr;
        }
    }

    // 获取字节数
    size_t get_size(EC_GROUP *curve, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        size_t size = 0;
        if (Sum_D != nullptr)
        {
            size += EC_POINT_point2oct(curve, Sum_D, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        }
        if (Sum != nullptr)
        {
            size += BN_bn2mpi(Sum, NULL);
        }
        size += EC_POINT_point2oct(curve, GK, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, GK_, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, pkA__, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        size += BN_bn2mpi(skA_hat_, NULL);
        BN_CTX_end(ctx);
        return size;
    }
};