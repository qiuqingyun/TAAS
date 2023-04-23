#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <iostream>
#include "ec.h"
#include "hash.h"
#include "User.h"

int main()
{
    // 初始化 OpenSSL
    OpenSSL_add_all_algorithms();
    BN_CTX *ctx = BN_CTX_new();

    /* Global */
    W1 w1(ctx); // 公共参数

    /* User */
    // 生成用户数量
    int user_count = 8;
    // 存储所有用户的数据
    BIGNUM *u[user_count];        // 所有用户的身份标识
    BIGNUM *r[user_count];        // 所有用户的随机数
    EC_POINT *U_user[user_count]; // 所有用户的加密证据
    // 循环生成用户数据
    for (int i = 0; i < user_count; i++)
    {
        // 生成随机用户
        User user(&w1);
        // 计算Ui和Vi
        user.compute(ctx);
        // 存储用户数据
        u[i] = user.get_ui();
        r[i] = user.get_ri();
        U_user[i] = user.get_Ui();
    }

    /* Advertiser */
    // 生成随机数k1，k'，x'和y'
    BIGNUM *k1 = BN_rand(256);
    BIGNUM *k_ = BN_rand(256);
    BIGNUM *x_ = BN_rand(256);
    BIGNUM *y_ = BN_rand(256);

    // 选择 n 个随机数 {a1,a2,...,an}，其中n为用户数量
    BIGNUM *a[user_count];
    for (int i = 0; i < user_count; i++)
    {
        a[i] = BN_rand(256);
    }

    // 计算 W = k1*G1
    EC_POINT *W = EC_POINT_new(w1.get_curve());
    EC_POINT_mul(w1.get_curve(), W, NULL, w1.get_G1(), k1, ctx);

    // 计算 Ui = ui*G_0 + ri*H0，其中i的范围是1到n
    EC_POINT *U[user_count];
    for (int i = 0; i < user_count; i++)
    {
        U[i] = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), U[i], NULL, w1.get_G0(), u[i], ctx);
        EC_POINT *temp = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), temp, NULL, w1.get_H0(), r[i], ctx);
        EC_POINT_add(w1.get_curve(), U[i], U[i], temp, ctx);
    }

    // 计算 Ai = k1*ui*G2，其中i的范围是1到n
    EC_POINT *A[user_count];
    for (int i = 0; i < user_count; i++)
    {
        A[i] = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), A[i], NULL, w1.get_G2(), u[i], ctx);
        EC_POINT_mul(w1.get_curve(), A[i], NULL, A[i], k1, ctx);
    }

    // 计算 Di = k1*Ui，其中i的范围是1到n
    EC_POINT *D[user_count];
    for (int i = 0; i < user_count; i++)
    {
        D[i] = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), D[i], NULL, U[i], k1, ctx);
    }

    // 计算 U'= a1*U1 + a2*U2 + ... + an*Un
    EC_POINT *U_ = EC_POINT_new(w1.get_curve());
    EC_POINT_mul(w1.get_curve(), U_, NULL, U[0], a[0], ctx);
    for (int i = 1; i < user_count; i++)
    {
        EC_POINT *temp = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), temp, NULL, U[i], a[i], ctx);
        EC_POINT_add(w1.get_curve(), U_, U_, temp, ctx);
    }

    // 计算 C1 = k1*U'
    EC_POINT *C1 = EC_POINT_new(w1.get_curve());
    EC_POINT_mul(w1.get_curve(), C1, NULL, U_, k1, ctx);

    // 计算 C1' = k'*U'
    EC_POINT *C1_ = EC_POINT_new(w1.get_curve());
    EC_POINT_mul(w1.get_curve(), C1_, NULL, U_, k_, ctx);

    // 计算 W' = k'*G1
    EC_POINT *W_ = EC_POINT_new(w1.get_curve());
    EC_POINT_mul(w1.get_curve(), W_, NULL, w1.get_G1(), k_, ctx);

    // 设置公开参数组P0
    P0 p0(w1.get_curve(), W_, C1_);

    // 计算哈希值 S0 = hash(W1||P0)
    std::string combined = bind(w1.to_string(ctx), p0.to_string(ctx));
    BIGNUM *S0 = BN_hash(combined);

    // 计算 k_hat = S0*k1+k'
    BIGNUM *k_hat = BN_new();
    BN_mod_mul(k_hat, S0, k1, w1.get_order(), ctx);
    BN_mod_add(k_hat, k_hat, k_, w1.get_order(), ctx);

    // 计算 A' = x'*G2
    EC_POINT *A_ = EC_POINT_new(w1.get_curve());
    EC_POINT_mul(w1.get_curve(), A_, NULL, w1.get_G2(), x_, ctx);

    // 计算 D' = x'*G0 + y'*H0
    EC_POINT *D_ = EC_POINT_new(w1.get_curve());
    EC_POINT_mul(w1.get_curve(), D_, NULL, w1.get_G0(), x_, ctx);
    EC_POINT *temp = EC_POINT_new(w1.get_curve());
    EC_POINT_mul(w1.get_curve(), temp, NULL, w1.get_H0(), y_, ctx);
    EC_POINT_add(w1.get_curve(), D_, D_, temp, ctx);

    // 计算 x_hat = x' + S1*k1*u1 + S2*k1*u2 + ... + Sn*k1*un
    BIGNUM *x_hat = BN_new();
    BN_copy(x_hat, x_); // 将x'赋值给x_hat
    for (int i = 0; i < user_count; i++)
    {
        // 设置公开参数组Pi
        Pi pi(w1.get_curve(), A[i], D[i]);
        // 计算哈希值 Si = hash(i||W1||Pi)
        std::string combined = bind(std::to_string(i), w1.to_string(ctx), pi.to_string(ctx));
        BIGNUM *Si = BN_hash(combined);
        // 累加
        BIGNUM *temp = BN_new();
        BN_mod_mul(temp, Si, k1, w1.get_order(), ctx);
        BN_mod_mul(temp, temp, u[i], w1.get_order(), ctx);
        BN_mod_add(x_hat, x_hat, temp, w1.get_order(), ctx);
    }

    // 计算 y_hat = y' + S1*k1*r1 + S2*k1*r2 + ... + Sn*k1*rn
    BIGNUM *y_hat = BN_new();
    BN_copy(y_hat, y_); // 将y'赋值给y_hat
    for (int i = 0; i < user_count; i++)
    {
        // 设置公开参数组Pi
        Pi pi(w1.get_curve(), A[i], D[i]);
        // 计算哈希值 Si = hash(i||W1||Pi)
        std::string combined = bind(std::to_string(i), w1.to_string(ctx), pi.to_string(ctx));
        BIGNUM *Si = BN_hash(combined);
        // 累加
        BIGNUM *temp = BN_new();
        BN_mod_mul(temp, Si, k1, w1.get_order(), ctx);
        BN_mod_mul(temp, temp, r[i], w1.get_order(), ctx);
        BN_mod_add(y_hat, y_hat, temp, w1.get_order(), ctx);
    }

    /* Platform */
    EC_POINT *left = EC_POINT_new(w1.get_curve());
    EC_POINT *right = EC_POINT_new(w1.get_curve());

    // 验证等式是否成立: k_hat*G1 = S0*W + W'
    EC_POINT_mul(w1.get_curve(), left, NULL, w1.get_G1(), k_hat, ctx);
    EC_POINT_mul(w1.get_curve(), right, NULL, W, S0, ctx);
    EC_POINT_add(w1.get_curve(), right, right, W_, ctx);
    if (EC_POINT_cmp(w1.get_curve(), left, right, ctx) != 0)
    {
        std::cout << "fail #1" << std::endl;
        return 0;
    }

    // 验证等式是否成立: k_hat*U' = S0*C1 + C1'
    EC_POINT_mul(w1.get_curve(), left, NULL, U_, k_hat, ctx);
    EC_POINT_mul(w1.get_curve(), right, NULL, C1, S0, ctx);
    EC_POINT_add(w1.get_curve(), right, right, C1_, ctx);
    if (EC_POINT_cmp(w1.get_curve(), left, right, ctx) != 0)
    {
        std::cout << "fail #2" << std::endl;
        return 0;
    }

    // 验证等式是否成立: x_hat*G2 = A' + S1*A1 + S2*A2 + ... + Sn*An
    EC_POINT_mul(w1.get_curve(), left, NULL, w1.get_G2(), x_hat, ctx);
    // 将A'赋值给right
    EC_POINT_copy(right, A_);
    for (int i = 0; i < user_count; i++)
    {
        // 设置公开参数组Pi
        Pi pi(w1.get_curve(), A[i], D[i]);
        // 计算哈希值 Si = hash(i||W1||Pi)
        std::string combined = bind(std::to_string(i), w1.to_string(ctx), pi.to_string(ctx));
        BIGNUM *Si = BN_hash(combined);
        // 累加
        EC_POINT_mul(w1.get_curve(), temp, NULL, A[i], Si, ctx);
        EC_POINT_add(w1.get_curve(), right, right, temp, ctx);
    }
    if (EC_POINT_cmp(w1.get_curve(), left, right, ctx) != 0)
    {
        std::cout << "fail #3" << std::endl;
        return 0;
    }

    // 验证等式是否成立: x_hat*G0 + y_hat*H0 = D' + S1*D1 + S2*D2 + ... + Sn*Dn
    EC_POINT_mul(w1.get_curve(), left, NULL, w1.get_G0(), x_hat, ctx);
    EC_POINT_mul(w1.get_curve(), right, NULL, w1.get_H0(), y_hat, ctx);
    EC_POINT_add(w1.get_curve(), left, left, right, ctx);
    // 将D'赋值给right
    EC_POINT_copy(right, D_);
    for (int i = 0; i < user_count; i++)
    {
        // 设置公开参数组Pi
        Pi pi(w1.get_curve(), A[i], D[i]);
        // 计算哈希值 Si = hash(i||W1||Pi)
        std::string combined = bind(std::to_string(i), w1.to_string(ctx), pi.to_string(ctx));
        BIGNUM *Si = BN_hash(combined);
        // 累加
        EC_POINT_mul(w1.get_curve(), temp, NULL, D[i], Si, ctx);
        EC_POINT_add(w1.get_curve(), right, right, temp, ctx);
    }
    if (EC_POINT_cmp(w1.get_curve(), left, right, ctx) != 0)
    {
        std::cout << "fail #4" << std::endl;
        return 0;
    }

    // 输出验证结果
    std::cout << "pass" << std::endl;

    return 0;
}