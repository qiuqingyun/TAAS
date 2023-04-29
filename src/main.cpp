#include "User.h"
#include "Advertiser.h"
#include "Platform.h"
#include "ElGamal.h"
#include "hash.h"

int test_verify(int user_count);

int main(int argc, char *argv[])
{
    int user_count_advertiser = 2; // 广告主的用户数量
    if (argc == 2)
    {
        // 读取argv[1]并赋值到user_count
        user_count_advertiser = atoi(argv[1]);
    }

    int user_count_platform = std::ceil(user_count_advertiser * 1.1);     // 广告平台的用户数量
    int user_count_intersection = std::ceil(user_count_advertiser * 0.8); // 交集用户数量

    // 初始化 OpenSSL
    OpenSSL_add_all_algorithms();
    BN_CTX *ctx = BN_CTX_new();

    /* Global */
    W1 w1(ctx); // 公共参数

    Advertiser advertiser(&w1, user_count_advertiser);

    /* User */
    // 用户数据
    User_data **user_data_advertiser = new User_data *[user_count_advertiser]; // 广告主拥有的用户数据，包括u和r
    BIGNUM **user_id_platform = new BIGNUM *[user_count_platform];             // 广告平台拥有的用户身份标识
    // 随机生成用户数据
    BIGNUM *Sum = BN_new(); // 累加user_data_advertiser[i]->v作为Sum
    BN_zero(Sum);
    // 使用一个unordered_set来存储交集中的用户身份标识
    // std::unordered_set<std::string> user_id_intersection;
    for (int i = 0; i < user_count_intersection; ++i)
    {
        user_data_advertiser[i] = new User_data();
        user_data_advertiser[i]->u = BN_rand(256);
        user_data_advertiser[i]->r = BN_rand(256);
        user_data_advertiser[i]->v = BN_rand(16);
        user_id_platform[i] = BN_dup(user_data_advertiser[i]->u);
        BN_mod_add(Sum, Sum, user_data_advertiser[i]->v, w1.get_order(), ctx);
        // 将用户身份标识插入到unordered_set中
        // user_id_intersection.insert(BN_bn2hex(user_data_advertiser[i]->u));
    }
    // 继续生成剩余的用户数据
    for (int i = user_count_intersection; i < user_count_advertiser; ++i)
    {
        user_data_advertiser[i] = new User_data();
        user_data_advertiser[i]->u = BN_rand(256);
        user_data_advertiser[i]->r = BN_rand(256);
        user_data_advertiser[i]->v = BN_rand(16);
    }
    for (int i = user_count_intersection; i < user_count_platform; ++i)
    {
        user_id_platform[i] = BN_rand(256);
    }

    // 测试ElGamal加密
    bool test_elgamal = false;
    if (test_elgamal)
    {
        // 设置明文plaintext1=10, plaintext2=20
        BIGNUM *plaintext1 = BN_new();
        BIGNUM *plaintext2 = BN_new();
        BN_set_word(plaintext1, 10);
        BN_set_word(plaintext2, 20);
        // 加密plaintext1和plaintext2
        ElGamal_ciphertext *ciphertext1 = ElGamal_encrypt(&w1, plaintext1, ctx);
        ElGamal_ciphertext *ciphertext2 = ElGamal_encrypt(&w1, plaintext2, ctx);
        // 解密ciphertext1和ciphertext2
        EC_POINT *decrypted1 = ElGamal_decrypt(&w1, advertiser.get_skA(), ciphertext1, ctx);
        EC_POINT *decrypted2 = ElGamal_decrypt(&w1, advertiser.get_skA(), ciphertext2, ctx);
        // 计算plaintext1*Ga
        EC_POINT *plaintext1_Ga = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), plaintext1_Ga, NULL, w1.get_Ga(), plaintext1, ctx);
        // 计算plaintext2*Ga
        EC_POINT *plaintext2_Ga = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), plaintext2_Ga, NULL, w1.get_Ga(), plaintext2, ctx);
        // 打印plaintext1*Ga
        std::cout << "plaintext1_Ga: " << EC_POINT_point2hex(w1.get_curve(), plaintext1_Ga, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
        // 打印decrypted1
        std::cout << "decrypted1: " << EC_POINT_point2hex(w1.get_curve(), decrypted1, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
        // 打印plaintext2*Ga
        std::cout << "plaintext2_Ga: " << EC_POINT_point2hex(w1.get_curve(), plaintext2_Ga, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
        // 打印decrypted2
        std::cout << "decrypted2: " << EC_POINT_point2hex(w1.get_curve(), decrypted2, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
        // 计算ciphertext1+ciphertext2
        ElGamal_ciphertext *ciphertext_sum = new ElGamal_ciphertext();
        ElGamal_add(w1.get_curve(), ciphertext_sum, ciphertext1, ciphertext2, ctx);
        // 解密ciphertext_sum
        EC_POINT *decrypted_sum = ElGamal_decrypt(&w1, advertiser.get_skA(), ciphertext_sum, ctx);
        // 打印decrypted_sum
        std::cout << "decrypted_sum: " << EC_POINT_point2hex(w1.get_curve(), decrypted_sum, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
        // 计算plaintext1+plaintext2
        BIGNUM *plaintext_sum = BN_new();
        BN_add(plaintext_sum, plaintext1, plaintext2);
        // 计算(plaintext1+plaintext2)*Ga
        EC_POINT *plaintext_sum_Ga = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), plaintext_sum_Ga, NULL, w1.get_Ga(), plaintext_sum, ctx);
        // 打印plaintext_sum_Ga
        std::cout << "plaintext_sum_Ga: " << EC_POINT_point2hex(w1.get_curve(), plaintext_sum_Ga, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
    }

    // 计算Sum*Ga
    EC_POINT *Sum_d = EC_POINT_new(w1.get_curve());
    EC_POINT_mul(w1.get_curve(), Sum_d, NULL, w1.get_Ga(), Sum, ctx);
    // 打印Sum*Ga
    // std::cout << "Sum_d: " << EC_POINT_point2hex(w1.get_curve(), Sum_d, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;

    // 使用std::shuffle将user_id_platform进行随机排序
    std::shuffle(user_id_platform, user_id_platform + user_count_platform, std::default_random_engine(std::chrono::system_clock::now().time_since_epoch().count()));
    // 使用std::shuffle将user_data_advertiser进行随机排序
    std::shuffle(user_data_advertiser, user_data_advertiser + user_count_advertiser, std::default_random_engine(std::chrono::system_clock::now().time_since_epoch().count()));

    std::unordered_map<std::string, User_evidence *> *U_Evidence = new std::unordered_map<std::string, User_evidence *>(); // 使用一个map存储所有用户的证据
    size_t evidence_size = 0;                                                                                              // 用户证据大小
    std::chrono::microseconds duration_user(0);                                                                            // 用户生成时间
    // 生成用户数据
    for (int i = 0; i < user_count_advertiser; i++)
    {
        // 生成随机用户
        BN_CTX *ctx_user = BN_CTX_new();
        User user(&w1, user_data_advertiser[i]->u, user_data_advertiser[i]->r, user_data_advertiser[i]->v);
        auto start_user = std::chrono::high_resolution_clock::now(); // 记录开始时间
        // 计算Ui和Vi
        user.compute(ctx_user);
        auto end_user = std::chrono::high_resolution_clock::now();                                     // 记录结束时间
        duration_user += std::chrono::duration_cast<std::chrono::microseconds>(end_user - start_user); // 累加运行时间
        // 存储用户证据
        U_Evidence->insert(std::make_pair(
            EC_POINT_point2hex(w1.get_curve(), user.get_user_evidence()->U, POINT_CONVERSION_COMPRESSED, ctx_user),
            user.get_user_evidence()));
        // U_Evidence[EC_POINT_point2hex(w1.get_curve(), user.get_user_evidence()->U, POINT_CONVERSION_COMPRESSED, ctx_user)] = user.get_user_evidence();
        // 累加证据大小
        evidence_size += user.get_evidence_size(ctx_user);
        // 打印 Ui-Vi
        // std::cout << "(Ui,Vi): (" << EC_POINT_point2hex(w1.get_curve(), user.get_user_evidence()->U, POINT_CONVERSION_COMPRESSED, ctx_user) << ", " << user.get_user_evidence()->V->to_string(w1.get_curve(), ctx) << ")" << std::endl;
        // 释放内存
        BN_CTX_free(ctx_user);
    }
    // std::cout << std::endl;

    /* A0 */
    // 验证部分的内容
    // 生成随机数 k1
    BIGNUM *k1 = BN_rand(256);
    // 保存向量A
    EC_POINT **A = new EC_POINT *[user_count_advertiser];
    // 使用unordered_map存储Ai与Vi的关系，并分配在堆上
    std::unordered_map<std::string, ElGamal_ciphertext *> *A_V = new std::unordered_map<std::string, ElGamal_ciphertext *>[user_count_advertiser];
    for (int i = 0; i < user_count_advertiser; i++)
    {
        // 计算 Ai = k1*ui*G2
        A[i] = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), A[i], NULL, w1.get_G2(), k1, ctx);
        EC_POINT_mul(w1.get_curve(), A[i], NULL, A[i], user_data_advertiser[i]->u, ctx);
        // 计算 Ui = ui*G0 + ri*H0
        EC_POINT *Ui = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), Ui, NULL, w1.get_G0(), user_data_advertiser[i]->u, ctx);
        EC_POINT *temp = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), temp, NULL, w1.get_H0(), user_data_advertiser[i]->r, ctx);
        EC_POINT_add(w1.get_curve(), Ui, Ui, temp, ctx);
        // 利用 Ui 从 U_Evidence 中找到对应的证据Vi
        ElGamal_ciphertext *Vi = U_Evidence->at(EC_POINT_point2hex(w1.get_curve(), Ui, POINT_CONVERSION_COMPRESSED, ctx))->V;
        // 保存 Ai 与 Vi 的关系
        // A_V[EC_POINT_point2hex(w1.get_curve(), A[i], POINT_CONVERSION_COMPRESSED, ctx)] = Vi;
        A_V->insert(std::make_pair(EC_POINT_point2hex(w1.get_curve(), A[i], POINT_CONVERSION_COMPRESSED, ctx), Vi));
        // 打印 Ui-Ai-Vi
        // std::cout << "(Ui,Ai,Vi): (" << EC_POINT_point2hex(w1.get_curve(), Ui, POINT_CONVERSION_COMPRESSED, ctx) << ", " << EC_POINT_point2hex(w1.get_curve(), A[i], POINT_CONVERSION_COMPRESSED, ctx) << ", " << Vi->to_string(w1.get_curve(), ctx) << ")" << std::endl;

        // 判断ui是否在user_id_intersection中，若在则打印
        // if (std::find(user_id_intersection.begin(), user_id_intersection.end(), BN_bn2hex(user_data_advertiser[i]->u)) != user_id_intersection.end())
        // {
        //     std::cout << "(Ui,Ai,Vi): (" << EC_POINT_point2hex(w1.get_curve(), Ui, POINT_CONVERSION_COMPRESSED, ctx) << ", " << EC_POINT_point2hex(w1.get_curve(), A[i], POINT_CONVERSION_COMPRESSED, ctx) << ", " << Vi->to_string(w1.get_curve(), ctx) << ")" << std::endl;
        // }
        // 打印Vi
        // std::cout << "Vi: " << Vi->to_string(w1.get_curve(), ctx) << std::endl;
        // 释放内存
        EC_POINT_free(Ui);
        EC_POINT_free(temp);
    }
    // std::cout << std::endl;

    /* P1 */
    // 输出结果变量
    EC_POINT *P_ = nullptr;
    EC_POINT **P = nullptr;
    // 选择随机数k2，k3
    BIGNUM *k2 = BN_rand(256);
    BIGNUM *k3 = BN_rand(256);
    BIGNUM *Z_hat = nullptr;
    {
        // 选择随机数Z'
        BIGNUM *Z_ = BN_rand(256);
        // 计算 P'=Z'*G2
        P_ = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), P_, NULL, w1.get_G2(), Z_, ctx);
        // 设置 Z_hat=Z'
        Z_hat = BN_dup(Z_);
        // 保存向量P
        P = new EC_POINT *[user_count_platform];
        for (int j = 0; j < user_count_platform; ++j)
        {
            // 计算 Pj=k3*Wj*G2
            P[j] = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), P[j], NULL, w1.get_G2(), k3, ctx);
            EC_POINT_mul(w1.get_curve(), P[j], NULL, P[j], user_id_platform[j], ctx);
            // 计算哈希值 t_j=H(j||W1||P')
            std::string combined = str_bind(
                std::to_string(j),
                w1.to_string(ctx),
                EC_POINT_point2hex(w1.get_curve(), P_, POINT_CONVERSION_COMPRESSED, ctx));
            BIGNUM *t_j = BN_hash(combined);
            // 计算 Z_hat = Z_hat + tj*k3*Wj
            BIGNUM *temp = BN_new();
            BN_mul(temp, t_j, k3, ctx);
            BN_mul(temp, temp, user_id_platform[j], ctx);
            BN_add(Z_hat, Z_hat, temp);
            BN_free(temp);
            BN_free(t_j);
        }
    }

    /* A2 */
    // 输出结果变量
    ElGamal_ciphertext **C = nullptr;
    ElGamal_ciphertext **C_ = nullptr;
    EC_POINT **CA = nullptr;
    EC_POINT **CB = nullptr;
    EC_POINT **CD_ = nullptr;
    BIGNUM *E = nullptr;
    ElGamal_ciphertext *F = nullptr;
    EC_POINT **Q = nullptr;
    EC_POINT *GS_ = nullptr;
    EC_POINT *GS = nullptr;
    EC_POINT *pkA_ = nullptr;
    BIGNUM *skA_hat = nullptr;
    BIGNUM *skA_ = nullptr;
    {
        // 验证 Z_hat*G2 = P' + t1*P1 + t2*P2 + ... + tn*Pn
        {
            EC_POINT *left = EC_POINT_new(w1.get_curve());
            EC_POINT *right = EC_POINT_new(w1.get_curve());
            // 计算 Z_hat*G2
            EC_POINT_mul(w1.get_curve(), left, NULL, w1.get_G2(), Z_hat, ctx);
            // 赋值right=P'
            EC_POINT_copy(right, P_);
            // 计算 t1*P1 + t2*P2 + ... + tn*Pn
            for (int j = 0; j < user_count_platform; ++j)
            {
                // 计算哈希值 t_j=H(j||W1||P')
                std::string combined = str_bind(
                    std::to_string(j),
                    w1.to_string(ctx),
                    EC_POINT_point2hex(w1.get_curve(), P_, POINT_CONVERSION_COMPRESSED, ctx));
                BIGNUM *t_j = BN_hash(combined);
                // 计算 t_j*Pj
                EC_POINT *temp = EC_POINT_new(w1.get_curve());
                EC_POINT_mul(w1.get_curve(), temp, NULL, P[j], t_j, ctx);
                // 累加
                EC_POINT_add(w1.get_curve(), right, right, temp, ctx);
                // 释放内存
                EC_POINT_free(temp);
                BN_free(t_j);
            }
            // 比较
            if (EC_POINT_cmp(w1.get_curve(), left, right, ctx) != 0)
            {
                std::cout << "failed: A2" << std::endl;
                return 1;
            }
        }
        // 选择 m 个随机数 {r1,r2,...,rm}
        BIGNUM **r = new BIGNUM *[user_count_platform];
        // 选择 m 个随机数 {⍴1,⍴2,...,⍴m}
        BIGNUM **rho = new BIGNUM *[user_count_platform];
        // 选择 m 个随机数 {s1,s2,...,sm}
        BIGNUM **s = new BIGNUM *[user_count_platform];
        // 选择 m 个随机数 {t1,t2,...,tm}
        BIGNUM **t = new BIGNUM *[user_count_platform];
        for (int j = 0; j < user_count_platform; ++j)
        {
            r[j] = BN_rand(256);
            rho[j] = BN_rand(256);
            s[j] = BN_rand(256);
            t[j] = BN_rand(256);
        }
        // 选择随机数 skA'
        skA_ = BN_rand(256);
        // 选择一个包含从1到m所有整数的数组π，并将其顺序shuffle
        int *pi = new int[user_count_platform];
        for (int j = 0; j < user_count_platform; ++j)
        {
            pi[j] = j + 1;
        }
        // 使用std::shuffle对数组π进行随机排序
        std::shuffle(pi, pi + user_count_platform, std::default_random_engine(std::random_device()()));
        // 保存密文C
        C = new ElGamal_ciphertext *[user_count_platform];
        for (int j = 0; j < user_count_platform; ++j)
        {
            // 计算ElGamal密文 Cj = (k1*Pj + rj*pkA , rj*Ha)
            C[j] = new ElGamal_ciphertext();
            C[j]->C1 = EC_POINT_new(w1.get_curve());
            C[j]->C2 = EC_POINT_new(w1.get_curve());
            EC_POINT *temp = EC_POINT_new(w1.get_curve());
            // 计算 k1*Pj
            EC_POINT_mul(w1.get_curve(), C[j]->C1, NULL, P[j], k1, ctx);
            // 计算 rj*pkA
            EC_POINT_mul(w1.get_curve(), temp, NULL, w1.get_pkA(), r[j], ctx);
            // 计算 C1 = k1*Pj + rj*pkA
            EC_POINT_add(w1.get_curve(), C[j]->C1, C[j]->C1, temp, ctx);
            // 计算 C2 = rj*Ha
            EC_POINT_mul(w1.get_curve(), C[j]->C2, NULL, w1.get_Ha(), r[j], ctx);
            // 释放内存
            EC_POINT_free(temp);
        }
        // 保存密文C'
        C_ = new ElGamal_ciphertext *[user_count_platform];
        // 保存密文CA
        CA = new EC_POINT *[user_count_platform];
        // 保存向量π
        BIGNUM **pi_ = new BIGNUM *[user_count_platform];
        for (int j = 0; j < user_count_platform; ++j)
        {
            // 计算 Cj' = (⍴j*pkA, ⍴j*Ha) + C[πj]
            C_[j] = new ElGamal_ciphertext();
            C_[j]->C1 = EC_POINT_new(w1.get_curve());
            C_[j]->C2 = EC_POINT_new(w1.get_curve());
            // 计算 ⍴j*pkA
            EC_POINT_mul(w1.get_curve(), C_[j]->C1, NULL, w1.get_pkA(), rho[j], ctx);
            // 计算 ⍴j*Ha
            EC_POINT_mul(w1.get_curve(), C_[j]->C2, NULL, w1.get_Ha(), rho[j], ctx);
            // 计算 Cj' = (⍴j*pkA, ⍴j*Ha) + C[πj]
            ElGamal_add(w1.get_curve(), C_[j], C_[j], C[pi[j] - 1], ctx);
            // 计算 CAj = πj*G2 + sj*Ha
            CA[j] = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), CA[j], NULL, w1.get_Ha(), s[j], ctx);
            EC_POINT *temp = EC_POINT_new(w1.get_curve());
            // 将πj转化为BIGNUM
            pi_[j] = BN_new();
            BN_set_word(pi_[j], pi[j]);
            EC_POINT_mul(w1.get_curve(), temp, NULL, w1.get_G2(), pi_[j], ctx);
            EC_POINT_add(w1.get_curve(), CA[j], CA[j], temp, ctx);
            // 释放内存
            EC_POINT_free(temp);
        }
        // 计算哈希值 x=H(W1||CA1)
        std::string combined = str_bind(
            w1.to_string(ctx),
            EC_POINT_point2hex(w1.get_curve(), CA[0], POINT_CONVERSION_COMPRESSED, ctx));
        BIGNUM *x = BN_hash(combined);
        // 保存密文CB
        CB = new EC_POINT *[user_count_platform];
        // 保存向量B
        BIGNUM **B = new BIGNUM *[user_count_platform];
        for (int j = 0; j < user_count_platform; ++j)
        {
            // 计算 Bj = x^{πj}
            B[j] = BN_new();
            BN_mod_exp(B[j], x, pi_[j], w1.get_order(), ctx);
            // 计算 CBj = Bj*G2 + tj*Ha
            CB[j] = EC_POINT_new(w1.get_curve());
            EC_POINT *temp = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), CB[j], NULL, w1.get_G2(), B[j], ctx);
            EC_POINT_mul(w1.get_curve(), temp, NULL, w1.get_Ha(), t[j], ctx);
            EC_POINT_add(w1.get_curve(), CB[j], CB[j], temp, ctx);
            // 释放内存
            EC_POINT_free(temp);
        }
        // 计算哈希值 y=H(1||W1||CB1)
        combined = str_bind(
            "1",
            w1.to_string(ctx),
            EC_POINT_point2hex(w1.get_curve(), CB[0], POINT_CONVERSION_COMPRESSED, ctx));
        BIGNUM *y = BN_hash(combined);
        // 计算哈希值 z=H(2||W1||CB1)
        combined = str_bind(
            "2",
            w1.to_string(ctx),
            EC_POINT_point2hex(w1.get_curve(), CB[0], POINT_CONVERSION_COMPRESSED, ctx));
        BIGNUM *z = BN_hash(combined);
        // 设置 E=1
        E = BN_new();
        BN_one(E);
        // 保存向量CD'
        CD_ = new EC_POINT *[user_count_platform];
        for (int j = 0; j < user_count_platform; ++j)
        {
            // 计算 Dj' = Bj + y*πj - z
            BIGNUM *Dj_ = BN_new();
            BN_mod_mul(Dj_, y, pi_[j], w1.get_order(), ctx);
            BN_mod_add(Dj_, Dj_, B[j], w1.get_order(), ctx);
            BN_mod_sub(Dj_, Dj_, z, w1.get_order(), ctx);
            // 计算 CDj' = Dj'*G2 + (y*sj + tj)*Ha
            CD_[j] = EC_POINT_new(w1.get_curve());
            EC_POINT *temp = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), CD_[j], NULL, w1.get_G2(), Dj_, ctx); // Dj'*G2
            EC_POINT_mul(w1.get_curve(), temp, NULL, w1.get_Ha(), y, ctx);     // y*Ha
            EC_POINT_mul(w1.get_curve(), temp, NULL, temp, s[j], ctx);         // y*sj*Ha
            EC_POINT_add(w1.get_curve(), CD_[j], CD_[j], temp, ctx);           // Dj'*G2 + y*sj*Ha
            EC_POINT_mul(w1.get_curve(), temp, NULL, w1.get_Ha(), t[j], ctx);  // tj*Ha
            EC_POINT_add(w1.get_curve(), CD_[j], CD_[j], temp, ctx);           // Dj'*G2 + y*sj*Ha + tj*Ha
            // 计算 E = E*Dj'
            BN_mod_mul(E, E, Dj_, w1.get_order(), ctx);
            // 释放内存
            EC_POINT_free(temp);
            BN_free(Dj_);
        }
        // 计算 ⍴' = -(⍴1*B1 + ⍴2*B2 + ... + ⍴m*Bm)
        BIGNUM *rho_ = BN_new();
        BN_zero(rho_);
        for (int j = 0; j < user_count_platform; ++j)
        {
            BIGNUM *temp = BN_new();
            BN_mod_mul(temp, rho[j], B[j], w1.get_order(), ctx);
            BN_mod_add(rho_, rho_, temp, w1.get_order(), ctx);
            BN_free(temp);
        }
        BN_mod_sub(rho_, w1.get_order(), rho_, w1.get_order(), ctx);
        // 保存向量 Q
        Q = new EC_POINT *[user_count_platform];
        // 计算 F = (⍴'*pkA, ⍴'*Ha) + B1*C1' + B2*C2' + ... + Bm*Cm'
        F = new ElGamal_ciphertext(w1.get_curve(), w1.get_pkA(), w1.get_Ha());
        ElGamal_mul(w1.get_curve(), F, F, rho_, ctx);
        for (int j = 0; j < user_count_platform; ++j)
        {
            // 计算 Bj*Cj'
            ElGamal_ciphertext *temp_F = new ElGamal_ciphertext();
            ElGamal_mul(w1.get_curve(), temp_F, C_[j], B[j], ctx);
            // 计算 F = F + Bj*Cj'
            ElGamal_add(w1.get_curve(), F, F, temp_F, ctx);
            // 计算 Qj = Cj1 + (Cj2*skA)^{-1}
            Q[j] = EC_POINT_new(w1.get_curve());
            EC_POINT *temp = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp, NULL, C_[j]->C2, advertiser.get_skA(), ctx); // Cj2*skA
            EC_POINT_invert(w1.get_curve(), temp, ctx);                                     // (Cj2*skA)^{-1}
            EC_POINT_add(w1.get_curve(), Q[j], C_[j]->C1, temp, ctx);                       // Cj1 + (Cj2*skA)^{-1}
            // 释放内存
            EC_POINT_free(temp);
            delete temp_F;
        }
        // 计算 GS = skA*G2
        GS = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), GS, NULL, w1.get_G2(), advertiser.get_skA(), ctx);
        // 计算 GS' = skA'*G2
        GS_ = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), GS_, NULL, w1.get_G2(), skA_, ctx);
        // 计算 pkA' = skA'*Ha
        pkA_ = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), pkA_, NULL, w1.get_Ha(), skA_, ctx);
        // 计算哈希值 ts=H(W1||GS'||pkA')
        combined = str_bind(
            w1.to_string(ctx),
            EC_POINT_point2hex(w1.get_curve(), GS_, POINT_CONVERSION_COMPRESSED, ctx),
            EC_POINT_point2hex(w1.get_curve(), pkA_, POINT_CONVERSION_COMPRESSED, ctx));
        BIGNUM *ts = BN_hash(combined);
        // 计算 skA_hat = ts*skA + skA'
        skA_hat = BN_new();
        BN_mod_mul(skA_hat, ts, advertiser.get_skA(), w1.get_order(), ctx);
        BN_mod_add(skA_hat, skA_hat, skA_, w1.get_order(), ctx);
        // 释放内存
        BN_free(ts);
        BN_free(rho_);
        BN_free(x);
        BN_free(y);
        BN_free(z);
        // 释放r,⍴,s,t,π,B
        for (int j = 0; j < user_count_platform; ++j)
        {
            BN_free(r[j]);
            BN_free(rho[j]);
            BN_free(s[j]);
            BN_free(t[j]);
            BN_free(pi_[j]);
            BN_free(B[j]);
        }
        delete[] r;
        delete[] rho;
        delete[] s;
        delete[] t;
        delete[] pi_;
        delete[] pi;
        delete[] B;
        // BN_free(skA_);
    }

    /* P3 */
    // 输出结果变量
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
    {
        // 验证上一轮的计算
        {
            // 计算哈希值x,y,z和ts
            std::string combined = str_bind(
                w1.to_string(ctx),
                EC_POINT_point2hex(w1.get_curve(), CA[0], POINT_CONVERSION_COMPRESSED, ctx));
            BIGNUM *x = BN_hash(combined);
            combined = str_bind(
                "1",
                w1.to_string(ctx),
                EC_POINT_point2hex(w1.get_curve(), CB[0], POINT_CONVERSION_COMPRESSED, ctx));
            BIGNUM *y = BN_hash(combined);
            combined = str_bind(
                "2",
                w1.to_string(ctx),
                EC_POINT_point2hex(w1.get_curve(), CB[0], POINT_CONVERSION_COMPRESSED, ctx));
            BIGNUM *z = BN_hash(combined);
            combined = str_bind(
                w1.to_string(ctx),
                EC_POINT_point2hex(w1.get_curve(), GS_, POINT_CONVERSION_COMPRESSED, ctx),
                EC_POINT_point2hex(w1.get_curve(), pkA_, POINT_CONVERSION_COMPRESSED, ctx));
            BIGNUM *ts = BN_hash(combined);
            // 保存向量CD
            EC_POINT **CD = new EC_POINT *[user_count_platform];
            for (int j = 0; j < user_count_platform; ++j)
            {
                // 计算 CDj = y*CAj + CBj - z*G2
                CD[j] = EC_POINT_new(w1.get_curve());
                EC_POINT *temp = EC_POINT_new(w1.get_curve());
                EC_POINT_mul(w1.get_curve(), temp, NULL, CA[j], y, ctx); // y*CAj
                EC_POINT_add(w1.get_curve(), CD[j], temp, CB[j], ctx);   // y*CAj + CBj
                EC_POINT_mul(w1.get_curve(), temp, NULL, w1.get_G2(), z, ctx);
                EC_POINT_invert(w1.get_curve(), temp, ctx); // -z*G2
                EC_POINT_add(w1.get_curve(), CD[j], CD[j], temp, ctx);
            }
            // 验证向量CD_和CD中的元素是否相等
            for (int j = 0; j < user_count_platform; ++j)
            {
                // 比较CD_[j]和CD[j]
                if (EC_POINT_cmp(w1.get_curve(), CD_[j], CD[j], ctx) != 0)
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
                BN_mod_exp(temp1, x, j_bn, w1.get_order(), ctx);      // x^j
                BN_mod_mul(temp2, y, j_bn, w1.get_order(), ctx);      // y*j
                BN_mod_add(temp1, temp1, temp2, w1.get_order(), ctx); // x^j + y*j
                BN_mod_sub(temp2, temp1, z, w1.get_order(), ctx);     // x^j + y*j - z
                BN_mod_mul(E_, E_, temp2, w1.get_order(), ctx);       // E' *= x^j + y*j - z
                // 释放内存
                BN_free(j_bn);
                BN_free(temp1);
                BN_free(temp2);
            }
            // 比较 E 和 E_
            if (BN_cmp(E, E_) != 0)
            {
                std::cout << "failed: P3" << std::endl;
                std::cout << "E != E_" << std::endl;
                // return 1;
            }
            // 验证 F = C1*x^1 + C2*x^2 + ... + Cm*x^m
            // 赋值 F' = C1*x^1
            ElGamal_ciphertext *F_ = new ElGamal_ciphertext(w1.get_curve(), C[0]->C1, C[0]->C2);
            ElGamal_mul(w1.get_curve(), F_, F_, x, ctx);
            for (int j = 1; j < user_count_platform; ++j)
            {
                // 计算 Cj*x^j
                // 将j转换为BIGNUM
                BIGNUM *j_bn = BN_new();
                BN_set_word(j_bn, j + 1);
                // 计算 x^j
                BIGNUM *temp = BN_new();
                BN_mod_exp(temp, x, j_bn, w1.get_order(), ctx);
                // 计算 Cj*x^j
                ElGamal_ciphertext *temp_c = new ElGamal_ciphertext();
                ElGamal_mul(w1.get_curve(), temp_c, C[j], temp, ctx);
                // 计算 F' += Cj*x^j
                ElGamal_add(w1.get_curve(), F_, F_, temp_c, ctx);
                // 释放内存
                BN_free(j_bn);
                BN_free(temp);
                delete temp_c;
            }
            // 比较 F 和 F_
            if (EC_POINT_cmp(w1.get_curve(), F->C1, F_->C1, ctx) != 0 || EC_POINT_cmp(w1.get_curve(), F->C2, F_->C2, ctx) != 0)
            {
                std::cout << "failed: P3" << std::endl;
                std::cout << "F != F_" << std::endl;
                return 1;
            }
            // 验证 skA_hat*G2 = ts*GS + GS'
            EC_POINT *left = EC_POINT_new(w1.get_curve());
            EC_POINT *right = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), left, NULL, w1.get_G2(), skA_hat, ctx); // skA_hat*G2
            EC_POINT_mul(w1.get_curve(), right, NULL, GS, ts, ctx);              // ts*GS
            EC_POINT_add(w1.get_curve(), right, right, GS_, ctx);                // ts*GS + GS'
            // 打印left和right
            // std::cout << "left: " << EC_POINT_point2hex(w1.get_curve(), left, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
            // std::cout << "right: " << EC_POINT_point2hex(w1.get_curve(), right, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
            // 比较 left 和 right
            if (EC_POINT_cmp(w1.get_curve(), left, right, ctx) != 0)
            {
                std::cout << "failed: P3" << std::endl;
                std::cout << "skA_hat*G2 != ts*GS + GS'" << std::endl;
                return 1;
            }
            // 验证 skA_hat*Ha = ts*pkA + pkA'
            EC_POINT_mul(w1.get_curve(), left, NULL, w1.get_Ha(), skA_hat, ctx); // skA_hat*Ha
            EC_POINT_mul(w1.get_curve(), right, NULL, w1.get_pkA(), ts, ctx);    // ts*pkA
            EC_POINT_add(w1.get_curve(), right, right, pkA_, ctx);               // ts*pkA + pkA'
            // 比较 left 和 right
            if (EC_POINT_cmp(w1.get_curve(), left, right, ctx) != 0)
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
        Q_ = EC_POINT_new(w1.get_curve());
        // 保存向量J
        J = new EC_POINT *[user_count_platform];
        for (int j = 0; j < user_count_platform; ++j)
        {
            // 计算 Jj = k2*Qj
            J[j] = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), J[j], NULL, Q[j], k2, ctx);
            // 计算 Q' = Q' + bj*Qj
            EC_POINT *temp = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp, NULL, Q[j], b[j], ctx);
            EC_POINT_add(w1.get_curve(), Q_, Q_, temp, ctx);
            // 释放内存
            EC_POINT_free(temp);
        }
        // 计算 C2 = k2*Q'
        C2 = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), C2, NULL, Q_, k2, ctx);
        // 计算 C2' = k2'*Q'
        C2_ = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), C2_, NULL, Q_, k2_, ctx);
        // 计算哈希值 tq = H(W_1||C2')
        std::string combine = str_bind(
            w1.to_string(ctx),
            EC_POINT_point2hex(w1.get_curve(), C2_, POINT_CONVERSION_COMPRESSED, ctx));
        BIGNUM *tq = BN_hash(combine);
        // 计算 k2_hat = tq*k2 + k2'
        k2_hat = BN_new();
        BN_mod_mul(k2_hat, tq, k2, w1.get_order(), ctx);
        BN_mod_add(k2_hat, k2_hat, k2_, w1.get_order(), ctx);
        // 设置 A'=0
        A_ = EC_POINT_new(w1.get_curve());
        // 保存向量L
        L = new EC_POINT *[user_count_advertiser];
        for (int i = 0; i < user_count_advertiser; ++i)
        {
            // 计算 A' = A' + ci*Ai
            EC_POINT *temp = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), temp, NULL, A[i], c[i], ctx);
            EC_POINT_add(w1.get_curve(), A_, A_, temp, ctx);
            // 计算 Li = k3*k2*Ai
            L[i] = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), L[i], NULL, A[i], k3, ctx);
            EC_POINT_mul(w1.get_curve(), L[i], NULL, L[i], k2, ctx);
            // 释放内存
            EC_POINT_free(temp);
        }
        // 计算 kq = k3*k2
        BIGNUM *kq = BN_new();
        BN_mod_mul(kq, k3, k2, w1.get_order(), ctx);
        // 计算 C3 = kq*A'
        C3 = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), C3, NULL, A_, kq, ctx);
        // 计算 C3' = kq'*A'
        C3_ = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), C3_, NULL, A_, kq_, ctx);
        // 计算哈希值 ta = H(W_1||C3')
        combine = str_bind(
            w1.to_string(ctx),
            EC_POINT_point2hex(w1.get_curve(), C3_, POINT_CONVERSION_COMPRESSED, ctx));
        BIGNUM *ta = BN_hash(combine);
        // 计算 kq_hat = ta*kq + kq'
        kq_hat = BN_new();
        BN_mod_mul(kq_hat, ta, kq, w1.get_order(), ctx);
        BN_mod_add(kq_hat, kq_hat, kq_, w1.get_order(), ctx);
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
    }

    /* A4 */
    // 输出结果变量
    EC_POINT *Sum_D = nullptr;
    EC_POINT *GK = nullptr;
    EC_POINT *GK_ = nullptr;
    EC_POINT *pkA__ = nullptr;
    BIGNUM *skA_hat_ = nullptr;
    {
        // 验证上一轮的计算
        {
            // 计算 tq=H(W1||C2')
            std::string combine = str_bind(
                w1.to_string(ctx),
                EC_POINT_point2hex(w1.get_curve(), C2_, POINT_CONVERSION_COMPRESSED, ctx));
            BIGNUM *tq = BN_hash(combine);
            // 计算 ta=H(W1||C3')
            combine = str_bind(
                w1.to_string(ctx),
                EC_POINT_point2hex(w1.get_curve(), C3_, POINT_CONVERSION_COMPRESSED, ctx));
            BIGNUM *ta = BN_hash(combine);
            // 验证 k2_hat*Q' = tq*C2 + C2'
            EC_POINT *left = EC_POINT_new(w1.get_curve());
            EC_POINT *right = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), left, NULL, Q_, k2_hat, ctx);
            EC_POINT_mul(w1.get_curve(), right, NULL, C2, tq, ctx);
            EC_POINT_add(w1.get_curve(), right, right, C2_, ctx);
            if (EC_POINT_cmp(w1.get_curve(), left, right, ctx) != 0)
            {
                std::cout << "failed: A4" << std::endl;
                std::cout << "A4: k2_hat*Q' != tq*C2 + C2'" << std::endl;
                return 1;
            }
            // 验证 kq_hat*A' = ta*C3 + C3'
            EC_POINT_mul(w1.get_curve(), left, NULL, A_, kq_hat, ctx);
            EC_POINT_mul(w1.get_curve(), right, NULL, C3, ta, ctx);
            EC_POINT_add(w1.get_curve(), right, right, C3_, ctx);
            if (EC_POINT_cmp(w1.get_curve(), left, right, ctx) != 0)
            {
                std::cout << "failed: A4" << std::endl;
                std::cout << "A4: kq_hat*A' != ta*C3 + C3'" << std::endl;
                return 1;
            }
        }
        // 使用unordered_map存储Li与Ai的关系，并将其分配在堆内存中
        std::unordered_map<std::string, std::string> *L_A = new std::unordered_map<std::string, std::string>();
        // std::unordered_map<std::string, std::string> L_A;
        for (int i = 0; i < user_count_advertiser; ++i)
        {
            L_A->insert(std::make_pair(
                EC_POINT_point2hex(w1.get_curve(), L[i], POINT_CONVERSION_COMPRESSED, ctx),
                EC_POINT_point2hex(w1.get_curve(), A[i], POINT_CONVERSION_COMPRESSED, ctx)));
        }
        // 将向量J与一个空ElGamal_ciphertext组合为pair，并存入向量X中
        std::string *X = new std::string[user_count_platform];
        for (int j = 0; j < user_count_platform; ++j)
        {
            X[j] = EC_POINT_point2hex(w1.get_curve(), J[j], POINT_CONVERSION_COMPRESSED, ctx);
        }
        // 将向量L与向量V中的元素一一组合为pair，并存入向量Y中
        std::string *Y = new std::string[user_count_advertiser];
        for (int i = 0; i < user_count_advertiser; ++i)
        {
            Y[i] = EC_POINT_point2hex(w1.get_curve(), L[i], POINT_CONVERSION_COMPRESSED, ctx);
        }
        // 对向量X进行排序
        std::sort(X, X + user_count_platform);
        // 打印向量J
        // std::cout << "X:" << std::endl;
        // for (int i = 0; i < user_count_platform; ++i)
        // {
        //     std::cout << X[i] << std::endl;
        // }
        // std::cout << std::endl;
        // 对向量Y进行排序
        std::sort(Y, Y + user_count_advertiser);
        // 打印向量Y
        // std::cout << "Y:" << std::endl;
        // for (int i = 0; i < user_count_advertiser; ++i)
        // {
        //     std::cout << Y[i] << std::endl;
        // }
        // std::cout << std::endl;
        // 定义交集向量
        std::vector<std::string> *intersection = new std::vector<std::string>();
        // 使用set_intersection计算向量J与向量X的交集，当向量J中的元素与向量X中元素的first相同时，将向量X的元素存入交集向量intersection中
        std::set_intersection(
            X, X + user_count_platform,
            Y, Y + user_count_advertiser,
            std::back_inserter(*intersection));
        // 打印交集向量
        // std::cout << "intersection:" << std::endl;
        // for (size_t i = 0; i < intersection.size(); ++i)
        // {
        //     std::cout << intersection[i] << std::endl;
        // }
        // std::cout << std::endl;
        // std::cout << "intersection size: " << intersection.size() << std::endl;
        // std::cout << "J size: " << user_count_platform << std::endl;
        // std::cout << "X size: " << user_count_advertiser << std::endl;

        // 同态累加交集向量中的 ElGamal_ciphertext 得到 Sum_E
        ElGamal_ciphertext *Sum_E = nullptr;
        if (intersection->size() > 0)
        {
            // 将Sum_E赋值为交集向量中的第一个元素在A_V中的value
            Sum_E = new ElGamal_ciphertext(w1.get_curve(), A_V->at(L_A->at(intersection->at(0))));
            // 打印 Ai-Vi
            // std::cout << "(Ai,Vi): (" << L_A->at(intersection[0]) << ", " << A_V->at(L_A->at(intersection[0]))->to_string(w1.get_curve(), ctx) << ")" << std::endl;
            // 循环累加交集向量中的 ElGamal_ciphertext
            for (size_t i = 1; i < intersection->size(); ++i)
            {
                // 打印 Ai-Vi
                // std::cout << "(Ai,Vi): (" << L_A->at(intersection[i]) << ", " << A_V->at(L_A->at(intersection[i]))->to_string(w1.get_curve(), ctx) << ")" << std::endl;
                ElGamal_add(w1.get_curve(), Sum_E, Sum_E, A_V->at(L_A->at(intersection->at(i))), ctx);
            }
        }
        else
        {
            // 生成变量0
            BIGNUM *zero = BN_new();
            BN_zero(zero);
            Sum_E = ElGamal_encrypt(&w1, zero, ctx);
            BN_free(zero);
        }
        // 解密Sum_E
        Sum_D = ElGamal_decrypt(&w1, advertiser.get_skA(), Sum_E, ctx);
        // 打印Sum_D
        // std::cout << "Sum_D: " << EC_POINT_point2hex(w1.get_curve(), Sum_D, POINT_CONVERSION_COMPRESSED, ctx) << std::endl;
        // 测试Sum_D是否等于Sum_d
        if (EC_POINT_cmp(w1.get_curve(), Sum_D, Sum_d, ctx) != 0)
        {
            std::cout << "failed: A4" << std::endl;
            std::cout << "Sum_D != Sum_d" << std::endl;
        }
        // 选择随机数 skA''
        BIGNUM *skA__ = BN_rand(256);
        // 计算 GK = skA*Ga
        GK = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), GK, NULL, w1.get_Ga(), advertiser.get_skA(), ctx);
        // 计算 GK' = skA''*Ga
        GK_ = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), GK_, NULL, w1.get_Ga(), skA__, ctx);
        // 计算 pkA'' = skA''*Ha
        pkA__ = EC_POINT_new(w1.get_curve());
        EC_POINT_mul(w1.get_curve(), pkA__, NULL, w1.get_Ha(), skA__, ctx);
        // 计算哈希值 tb = H(W1||GK'||pkA'')
        std::string combine = str_bind(
            w1.to_string(ctx),
            EC_POINT_point2hex(w1.get_curve(), GK_, POINT_CONVERSION_COMPRESSED, ctx),
            EC_POINT_point2hex(w1.get_curve(), pkA__, POINT_CONVERSION_COMPRESSED, ctx));
        BIGNUM *tb = BN_hash(combine);
        // 计算 skA_hat = tb*skA + skA'
        skA_hat_ = BN_new();
        BN_mod_mul(skA_hat_, tb, advertiser.get_skA(), w1.get_order(), ctx);
        BN_mod_add(skA_hat_, skA_hat_, skA__, w1.get_order(), ctx);
        // 释放内存L_A,X,Y,intersection,Sum_E,skA__,tb
        delete L_A;
        delete[] X;
        delete[] Y;
        delete intersection;
        delete Sum_E;
        BN_free(skA__);
        BN_free(tb);
    }

    /* P5 */
    {
        {
            // 计算哈希值 tb = H(W1||GK'||pkA'')
            std::string combine = str_bind(
                w1.to_string(ctx),
                EC_POINT_point2hex(w1.get_curve(), GK_, POINT_CONVERSION_COMPRESSED, ctx),
                EC_POINT_point2hex(w1.get_curve(), pkA__, POINT_CONVERSION_COMPRESSED, ctx));
            BIGNUM *tb = BN_hash(combine);
            // 验证 skA'_hat*Ga = tb*GK + GK'
            EC_POINT *left = EC_POINT_new(w1.get_curve());
            EC_POINT *right = EC_POINT_new(w1.get_curve());
            EC_POINT_mul(w1.get_curve(), left, NULL, w1.get_Ga(), skA_hat_, ctx);
            EC_POINT_mul(w1.get_curve(), right, NULL, GK, tb, ctx);
            EC_POINT_add(w1.get_curve(), right, right, GK_, ctx);
            if (EC_POINT_cmp(w1.get_curve(), left, right, ctx) != 0)
            {
                std::cout << "failed: P5" << std::endl;
                std::cout << "skA_hat_*Ga != tb*GK + GK'" << std::endl;
            }
            // 验证 skA'_hat*Ha = tb*pkA + pkA''
            EC_POINT_mul(w1.get_curve(), left, NULL, w1.get_Ha(), skA_hat_, ctx);
            EC_POINT_mul(w1.get_curve(), right, NULL, w1.get_pkA(), tb, ctx);
            EC_POINT_add(w1.get_curve(), right, right, pkA__, ctx);
            if (EC_POINT_cmp(w1.get_curve(), left, right, ctx) != 0)
            {
                std::cout << "failed: P5" << std::endl;
                std::cout << "skA_hat_*Ha != tb*pkA + pkA''" << std::endl;
            }
        }
    }

    return 0;
}

int test_verify(int user_count)
{
    // 初始化 OpenSSL
    OpenSSL_add_all_algorithms();
    BN_CTX *ctx = BN_CTX_new();

    /* Global */
    W1 w1(ctx); // 公共参数

    Advertiser advertiser(&w1, user_count);

    /* User */
    // 存储所有用户的数据
    User_data **user_data = new User_data *[user_count];             // 所有用户的数据
    User_evidence **user_evidence = new User_evidence *[user_count]; // 所有用户的证据
    size_t evidence_size = 0;                                        // 用户证据大小
    std::chrono::microseconds duration_user(0);                      // 用户生成时间
    // 循环生成用户数据

    // 循环生成用户数据
    // 并行化
#pragma omp parallel for
    for (int i = 0; i < user_count; i++)
    {
        // 生成随机用户
        BN_CTX *ctx_user = BN_CTX_new();
        User user(&w1);
        auto start_user = std::chrono::high_resolution_clock::now(); // 记录开始时间
        // 计算Ui和Vi
        user.compute(ctx_user);
        auto end_user = std::chrono::high_resolution_clock::now();                                     // 记录结束时间
        duration_user += std::chrono::duration_cast<std::chrono::microseconds>(end_user - start_user); // 累加运行时间
        // 存储用户数据
        user_data[i] = user.get_user_data();
        user_evidence[i] = user.get_user_evidence();
        // 累加证据大小
        evidence_size += user.get_evidence_size(ctx_user);
        // 释放内存
        BN_CTX_free(ctx_user);
    }

    // 计算用户时间的平均值
    duration_user /= user_count;
    // 计算证据的平均大小
    evidence_size /= user_count;

    /* 批量模式测试 */
    // 广告主
    auto start_advertiser = std::chrono::high_resolution_clock::now(); // 记录开始时间
    advertiser.set_user_data(user_data);
    // 计算广告主的证明
    advertiser.compute(ctx);
    auto end_advertiser = std::chrono::high_resolution_clock::now();                                                           // 记录结束时间
    auto duration_advertiser_batch = std::chrono::duration_cast<std::chrono::microseconds>(end_advertiser - start_advertiser); // 计算运行时间
    // 获取证明
    Proof *proof_batch = new Proof(w1.get_curve(), advertiser.get_proof());
    // 计算证明的尺寸
    size_t proof_size_batch = proof_batch->get_proof_size(user_count, w1.get_curve(), ctx);
    // 广告平台
    auto start_platform = std::chrono::high_resolution_clock::now(); // 记录开始时间
    Platform platform(&w1, user_count, proof_batch);
    // 验证广告主的证明
    bool result_batch = platform.compute(ctx);
    auto end_platform = std::chrono::high_resolution_clock::now();                                                       // 记录结束时间
    auto duration_platform_batch = std::chrono::duration_cast<std::chrono::microseconds>(end_platform - start_platform); // 计算运行时间
    // 释放内存
    delete proof_batch;

    /* 单个模式测试 */
    // 验证结果
    bool result_single = true;
    std::chrono::microseconds duration_advertiser_single(0); // 广告主生成时间
    std::chrono::microseconds duration_platform_single(0);   // 广告平台验证时间
    size_t proof_size_single = 0;                            // 证明的尺寸
    for (int i = 0; i < user_count; i++)
    {
        // 广告主
        User_data **user_data_temp = new User_data *[1];
        user_data_temp[0] = new User_data(user_data[i]);
        Advertiser advertiser_single(&w1, 1);
        advertiser_single.set_user_data(user_data_temp);
        auto start_advertiser_single = std::chrono::high_resolution_clock::now(); // 记录广告主开始时间
        // 计算广告主的证明
        advertiser_single.compute(ctx);
        auto end_advertiser_single = std::chrono::high_resolution_clock::now(); // 记录广告主结束时间
        // 获取证明
        Proof *proof_single = new Proof(w1.get_curve(), advertiser_single.get_proof());
        // 累加证明的尺寸
        proof_size_single += proof_single->get_proof_size(1, w1.get_curve(), ctx);
        // 广告平台
        Platform platform_single(&w1, 1, proof_single);
        auto start_platform_single = std::chrono::high_resolution_clock::now(); // 记录广告平台开始时间
        // 验证广告主的证明
        bool result_temp = platform_single.compute(ctx);
        auto end_platform_single = std::chrono::high_resolution_clock::now(); // 记录广告平台结束时间
        result_single &= result_temp;
        // 累加广告主和广告平台的时间
        duration_advertiser_single += std::chrono::duration_cast<std::chrono::microseconds>(end_advertiser_single - start_advertiser_single);
        duration_platform_single += std::chrono::duration_cast<std::chrono::microseconds>(end_platform_single - start_platform_single);
        // 释放内存
        delete user_data_temp[0];
        delete[] user_data_temp;
        delete proof_single;
    }

    // 释放内存
    for (int i = 0; i < user_count; i++)
    {
        delete user_data[i];
        delete user_evidence[i];
    }
    delete[] user_data;
    delete[] user_evidence;
    // 释放上下文
    BN_CTX_free(ctx);

    // 以JSON格式输出结果
    {
        float time_scale = 1000.0f * 1000.0f; // 时间单位换算
        float size_scale = 1024.0f;           // 尺寸单位换算
        std::cout << "{";
        // 批量验证结果
        std::cout << "\"input_size\": " << user_count << ","; // 用户数量
        if (result_batch)
        {
            std::cout << "\"result_batch\": true,"; // 验证成功
        }
        else
        {
            std::cout << "\"result_batch\": false,"; // 验证失败
        }
        // 单个验证结果
        if (result_single)
        {
            std::cout << "\"result_single\": true,"; // 验证成功
        }
        else
        {
            std::cout << "\"result_single\": false,"; // 验证失败
        }
        // 输出一个data对象，其中包括time对象和size对象
        std::cout << "\"data\": {";
        // time对象里包含用户时间、广告主时间和广告平台时间
        // 设置输出精度
        std::cout << std::fixed << std::setprecision(6);
        std::cout << "\"time\": {";
        std::cout << "\"user\": " << duration_user.count() / time_scale << ",";                           // 用户时间
        std::cout << "\"advertiser_batch\": " << duration_advertiser_batch.count() / time_scale << ",";   // 批量模式广告主时间
        std::cout << "\"platform_batch\": " << duration_platform_batch.count() / time_scale << ",";       // 批量模式广告平台时间
        std::cout << "\"advertiser_single\": " << duration_advertiser_single.count() / time_scale << ","; // 单个模式广告主时间
        std::cout << "\"platform_single\": " << duration_platform_single.count() / time_scale << "";      // 单个模式广告平台时间
        std::cout << "},";
        // size对象里包含证明尺寸
        // 设置输出精度
        std::cout << std::fixed << std::setprecision(3);
        std::cout << "\"size\": {";
        std::cout << "\"evidence\": " << evidence_size / size_scale << ",";        // 证据尺寸
        std::cout << "\"proof_batch\": " << proof_size_batch / size_scale << ",";  // 批量模式证明尺寸
        std::cout << "\"proof_single\": " << proof_size_single / size_scale << ""; // 单个模式证明尺寸
        std::cout << "}";
        std::cout << "}";
        std::cout << "}" << std::endl;
    }
    return 0;
}
