// User类，实现生成用户数据的功能
#pragma once
#include "base.h"
#include "ec.h"
#include "ElGamal.h"
#include "Messages.h"

class User
{
    W1 *w1;
    BIGNUM *ui, *ri, *vi;
    EC_POINT *Ui;
    ElGamal_ciphertext *Vi;

public:
    // 构造函数，接收W1，并生成随机的ui和ri
    User(W1 *w1) : w1(w1)
    {
        ui = BN_rand(256);
        ri = BN_rand(256);
        vi = BN_rand(32);
    }

    // 构造函数，接收W1，ui和ri并保存
    User(W1 *w1, BIGNUM *ui, BIGNUM *ri, BIGNUM *vi) : w1(w1)
    {
        this->ui = BN_dup(ui);
        this->ri = BN_dup(ri);
        this->vi = BN_dup(vi);
    }

    // 析构函数，释放内存
    ~User()
    {
        BN_free(ui);
        BN_free(ri);
        BN_free(vi);
        EC_POINT_free(Ui);
        delete Vi;
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
        // 加密Vi
        Vi = ElGamal_encrypt(w1, vi, ctx);
        BN_CTX_end(ctx);
        EC_POINT_free(temp1);
        EC_POINT_free(temp2);
    }

    // 获取证据的字节数，包括Ui, Vi
    size_t get_evidence_size(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        size_t size = 0;
        size += EC_POINT_point2oct(w1->get_curve(), Ui, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(w1->get_curve(), Vi->C1, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(w1->get_curve(), Vi->C2, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        size += BN_num_bytes(ui);
        size += BN_num_bytes(ri);
        BN_CTX_end(ctx);
        return size;
    }

    // get函数
    User_data *get_user_data()
    {
        User_data *user_data = new User_data;
        user_data->u = BN_dup(ui);
        user_data->r = BN_dup(ri);
        user_data->v = BN_dup(vi);
        return user_data;
    }
    User_evidence *get_user_evidence()
    {
        User_evidence *user_evidence = new User_evidence;
        user_evidence->U = EC_POINT_dup(Ui, w1->get_curve());
        user_evidence->V = new ElGamal_ciphertext(w1->get_curve(), Vi);
        return user_evidence;
    }
};