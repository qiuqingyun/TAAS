// User类，实现生成用户数据的功能
#pragma once
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include "ec.h"

class User
{
    W1 *w1;
    BIGNUM *ui, *ri;
    EC_POINT *Ui, *Vi;

public:
    // 构造函数，接收W1，并生成随机的ui和ri
    User(W1 *w1) : w1(w1)
    {
        ui = BN_rand(256);
        ri = BN_rand(256);
    }

    // 构造函数，接收W1，ui和ri并保存
    User(W1 *w1, BIGNUM *ui, BIGNUM *ri) : w1(w1), ui(ui), ri(ri) {}

    // 计算Ui和Vi
    void compute(BN_CTX *ctx)
    {
        // 初始化 Ui 和 Vi
        EC_POINT *Ui = EC_POINT_new(w1->get_curve());
        EC_POINT *Vi = EC_POINT_new(w1->get_curve());
        // 计算 Ui=ui*G0 + ri* H0
        EC_POINT *temp1 = EC_POINT_new(w1->get_curve());
        EC_POINT *temp2 = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), temp1, NULL, w1->get_G0(), ui, ctx); // temp1 = ui*G0
        EC_POINT_mul(w1->get_curve(), temp2, NULL, w1->get_H0(), ri, ctx); // temp2 = ri*H0
        EC_POINT_add(w1->get_curve(), Ui, temp1, temp2, ctx);
        // 计算 Vi (搁置)
    }

    // get函数
    BIGNUM *get_ui() { return ui; }
    BIGNUM *get_ri() { return ri; }
    EC_POINT *get_Ui() { return Ui; }
    EC_POINT *get_Vi() { return Vi; }
};