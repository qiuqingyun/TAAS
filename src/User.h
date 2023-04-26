// User类，实现生成用户数据的功能
#pragma once
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include "ec.h"

class User_data
{
public:
    BIGNUM *u, *r;
    // 构造函数
    User_data() {}

    // 深拷贝构造函数
    User_data(User_data *user_data)
    {
        u = BN_dup(user_data->u);
        r = BN_dup(user_data->r);
    }

    // 释放内存
    ~User_data()
    {
        BN_free(u);
        BN_free(r);
    }
};

class User_evidence
{
public:
    EC_POINT *U;
    std::pair<EC_POINT *, EC_POINT *> *V;

    // 释放内存
    ~User_evidence()
    {
        EC_POINT_free(U);
        EC_POINT_free(V->first);
        EC_POINT_free(V->second);
        delete V;
    }
};

class User
{
    W1 *w1;
    BIGNUM *ui, *ri, *vi;
    EC_POINT *Ui, **Vi;

public:
    // 构造函数，接收W1，并生成随机的ui和ri
    User(W1 *w1) : w1(w1)
    {
        ui = BN_rand(256);
        ri = BN_rand(256);
        vi = BN_rand(32);
    }

    // 构造函数，接收W1，ui和ri并保存
    User(W1 *w1, BIGNUM *ui, BIGNUM *ri) : w1(w1), ui(ui), ri(ri) {}

    // 析构函数，释放内存
    ~User()
    {
        BN_free(ui);
        BN_free(ri);
        BN_free(vi);
        EC_POINT_free(Ui);
        for (int i = 0; i < 2; i++)
            EC_POINT_free(Vi[i]);
        delete[] Vi;
    }

    // 计算Ui和Vi
    void compute(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        // 初始化 Ui
        Ui = EC_POINT_new(w1->get_curve());
        // 计算 Ui=ui*G0 + ri* H0
        EC_POINT *temp1 = EC_POINT_new(w1->get_curve());
        EC_POINT *temp2 = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), temp1, NULL, w1->get_G0(), ui, ctx); // temp1 = ui*G0
        EC_POINT_mul(w1->get_curve(), temp2, NULL, w1->get_H0(), ri, ctx); // temp2 = ri*H0
        EC_POINT_add(w1->get_curve(), Ui, temp1, temp2, ctx);
        // 初始化Vi
        Vi = new EC_POINT *[2];
        // 生成随机数 ri'
        BIGNUM *ri_ = BN_rand(32);
        // V1i = ri*Ga + ri'*pkA
        Vi[0] = EC_POINT_new(w1->get_curve());
        EC_POINT *temp3 = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), temp1, NULL, w1->get_Ga(), ri, ctx);   // temp1 = ri*Ga
        EC_POINT_mul(w1->get_curve(), temp2, NULL, w1->get_pkA(), ri_, ctx); // temp2 = ri'*pkA
        EC_POINT_add(w1->get_curve(), Vi[0], temp1, temp2, ctx);
        // V2i = ri'*Ha
        Vi[1] = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), Vi[1], NULL, w1->get_Ha(), ri_, ctx);
        BN_CTX_end(ctx);
        BN_free(ri_);
        EC_POINT_free(temp1);
        EC_POINT_free(temp2);
        EC_POINT_free(temp3);
    }

    // 获取证据的字节数，包括Ui, Vi
    size_t get_evidence_size(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        size_t size = 0;
        size += EC_POINT_point2oct(w1->get_curve(), Ui, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        for (int i = 0; i < 2; i++)
            size += EC_POINT_point2oct(w1->get_curve(), Vi[i], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        BN_CTX_end(ctx);
        return size;
    }

    // get函数
    User_data *get_user_data()
    {
        User_data *user_data = new User_data;
        user_data->u = BN_dup(ui);
        user_data->r = BN_dup(ri);
        return user_data;
    }
    User_evidence *get_user_evidence()
    {
        User_evidence *user_evidence = new User_evidence;
        user_evidence->U = EC_POINT_dup(Ui, w1->get_curve());
        user_evidence->V = new std::pair<EC_POINT *, EC_POINT *>;
        user_evidence->V->first = EC_POINT_dup(Vi[0], w1->get_curve());
        user_evidence->V->second = EC_POINT_dup(Vi[1], w1->get_curve());
        return user_evidence;
    }
};