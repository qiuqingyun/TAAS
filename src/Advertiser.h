#pragma once
#include "base.h"
#include "ec.h"
#include "hash.h"
#include "User.h"

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
    BIGNUM *skA, **u = nullptr, **r = nullptr;
    EC_POINT *pkA;
    // 证明Proof
    Proof *proof = nullptr;

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
        if (u != nullptr && r != nullptr)
        {
            for (int i = 0; i < user_count; i++)
            {
                BN_free(u[i]);
                BN_free(r[i]);
            }
            delete[] u;
            delete[] r;
        }
        if (proof != nullptr)
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

        // 计算 Ui = ui*G_0 + ri*H0
        proof->U = new EC_POINT *[user_count];
        // 计算 Ai = k1*ui*G2
        proof->A = new EC_POINT *[user_count];
        // 计算 Di = k1*Ui
        proof->D = new EC_POINT *[user_count];
        // 为Ui, Ai, Di分配空间
        for (int i = 0; i < user_count; i++)
        {
            proof->U[i] = EC_POINT_new(w1->get_curve());
            proof->A[i] = EC_POINT_new(w1->get_curve());
            proof->D[i] = EC_POINT_new(w1->get_curve());
        }

        // 计算 U'= a1*U1 + a2*U2 + ... + an*Un
        proof->U_ = EC_POINT_new(w1->get_curve());
        // 赋值 U' = 0
        EC_POINT_set_to_infinity(w1->get_curve(), proof->U_);
        // 计算 x_hat = x' + S1*k1*u1 + S2*k1*u2 + ... + Sn*k1*un
        proof->x_hat = BN_new();
        BN_copy(proof->x_hat, x_); // 将x'赋值给x_hat
        // 计算 y_hat = y' + S1*k1*r1 + S2*k1*r2 + ... + Sn*k1*rn
        proof->y_hat = BN_new();
        BN_copy(proof->y_hat, y_); // 将y'赋值给y_hat

        // 循环计算Ui，Ai，Di，U'，x_hat和y_hat
// 并行化
#pragma omp parallel for
        for (int i = 0; i < user_count; i++)
        {
            BN_CTX *temp_ctx = BN_CTX_new();
            // 初始化临时变量
            EC_POINT *temp_Ui1 = EC_POINT_new(w1->get_curve());
            EC_POINT *temp_Ui2 = EC_POINT_new(w1->get_curve());
            EC_POINT *temp_Ui = EC_POINT_new(w1->get_curve());
            EC_POINT *temp_Ai = EC_POINT_new(w1->get_curve());
            EC_POINT *temp_Di = EC_POINT_new(w1->get_curve());
            EC_POINT *temp_U_ = EC_POINT_new(w1->get_curve());
            BIGNUM *temp = BN_new();
            BIGNUM *temp_x_hat = BN_new();
            BIGNUM *temp_y_hat = BN_new();
            BIGNUM *ui = BN_new();
            BIGNUM *ri = BN_new();
            BIGNUM *ai = BN_new();
            // 加锁读取u[i]，r[i]和a[i]
#pragma omp critical
            {
                BN_copy(ui, u[i]);
                BN_copy(ri, r[i]);
                BN_copy(ai, a[i]);
            }
            // 计算Ui
            EC_POINT_mul(w1->get_curve(), temp_Ui1, NULL, w1->get_G0(), ui, temp_ctx);
            EC_POINT_mul(w1->get_curve(), temp_Ui2, NULL, w1->get_H0(), ri, temp_ctx);
            EC_POINT_add(w1->get_curve(), temp_Ui, temp_Ui1, temp_Ui2, temp_ctx);
            // 计算Ai
            EC_POINT_mul(w1->get_curve(), temp_Ai, NULL, w1->get_G2(), k1, temp_ctx);
            EC_POINT_mul(w1->get_curve(), temp_Ai, NULL, temp_Ai, ui, temp_ctx);
            // 计算Di
            EC_POINT_mul(w1->get_curve(), temp_Di, NULL, temp_Ui, k1, temp_ctx);
            // 计算U'
            EC_POINT_mul(w1->get_curve(), temp_U_, NULL, temp_Ui, ai, temp_ctx);
            // 设置公开参数组Pi
            Pi pi(w1->get_curve(), temp_Ai, temp_Di);
            // 计算哈希值 Si = hash(i||W1||Pi)
            std::string combined = bind(std::to_string(i), w1->to_string(temp_ctx), pi.to_string(temp_ctx));
            BIGNUM *Si = BN_hash(combined);
            BN_mod_mul(temp, Si, k1, w1->get_order(), temp_ctx);
            // 计算x_hat
            BN_mod_mul(temp_x_hat, temp, u[i], w1->get_order(), temp_ctx);
            // 计算y_hat
            BN_mod_mul(temp_y_hat, temp, r[i], w1->get_order(), temp_ctx);
            // 加锁，赋值Ui，Ai和Di并累加U'，x_hat和y_hat
#pragma omp critical
            {
                EC_POINT_copy(proof->U[i], temp_Ui);
                EC_POINT_copy(proof->A[i], temp_Ai);
                EC_POINT_copy(proof->D[i], temp_Di);

                EC_POINT_add(w1->get_curve(), proof->U_, proof->U_, temp_U_, temp_ctx);
                BN_mod_add(proof->x_hat, proof->x_hat, temp_x_hat, w1->get_order(), temp_ctx);
                BN_mod_add(proof->y_hat, proof->y_hat, temp_y_hat, w1->get_order(), temp_ctx);
            }
            // 释放临时变量
            EC_POINT_free(temp_Ui1);
            EC_POINT_free(temp_Ui2);
            EC_POINT_free(temp_Ui);
            EC_POINT_free(temp_Ai);
            EC_POINT_free(temp_Di);
            EC_POINT_free(temp_U_);
            BN_free(ui);
            BN_free(ri);
            BN_free(ai);
            BN_free(Si);
            BN_free(temp);
            BN_free(temp_x_hat);
            BN_free(temp_y_hat);
            BN_CTX_free(temp_ctx);
        }

        // 计算 W = k1*G1
        proof->W = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), proof->W, NULL, w1->get_G1(), k1, ctx);

        // 计算 W' = k'*G1
        proof->W_ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), proof->W_, NULL, w1->get_G1(), k_, ctx);

        // 计算 C1 = k1*U'
        proof->C1 = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), proof->C1, NULL, proof->U_, k1, ctx);

        // 计算 C1' = k'*U'
        proof->C1_ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), proof->C1_, NULL, proof->U_, k_, ctx);

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

        // 设置公开参数组P0
        P0 p0(w1->get_curve(), proof->W_, proof->C1_);

        // 计算哈希值 S0 = hash(W1||P0)
        std::string combined = bind(w1->to_string(ctx), p0.to_string(ctx));
        BIGNUM *S0 = BN_hash(combined);

        // 计算 k_hat = S0*k1+k'
        proof->k_hat = BN_new();
        BN_mod_mul(proof->k_hat, S0, k1, w1->get_order(), ctx);
        BN_mod_add(proof->k_hat, proof->k_hat, k_, w1->get_order(), ctx);

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