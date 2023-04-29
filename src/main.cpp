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

    // test_verify(user_count_advertiser);
    // return 0;

    int user_count_platform = std::ceil(user_count_advertiser * 1.0);     // 广告平台的用户数量
    int user_count_intersection = std::ceil(user_count_advertiser * 0.8); // 交集用户数量

    // 初始化 OpenSSL
    OpenSSL_add_all_algorithms();
    BN_CTX *ctx = BN_CTX_new();

    /* Global */
    W1 w1(ctx); // 公共参数

    Advertiser advertiser(&w1, user_count_advertiser, user_count_platform);

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
    advertiser.debug_set_Sum_d(Sum_d);

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
        evidence_size += user.get_evidence_size(ctx_user);
        // 释放内存
        BN_CTX_free(ctx_user);
    }

    // 广告主
    auto start_advertiser = std::chrono::high_resolution_clock::now(); // 记录开始时间
    advertiser.set_user_data(user_data_advertiser);
    advertiser.set_U_Evidence(U_Evidence);
    // 计算广告主的证明
    advertiser.proof_gen(ctx);
    auto end_advertiser = std::chrono::high_resolution_clock::now();                                                           // 记录结束时间
    auto duration_advertiser_batch = std::chrono::duration_cast<std::chrono::microseconds>(end_advertiser - start_advertiser); // 计算运行时间
    // 获取证明
    Proof *proof_batch = new Proof(w1.get_curve(), advertiser.get_proof());
    // 计算证明的尺寸
    size_t proof_size_batch = proof_batch->get_proof_size(user_count_advertiser, w1.get_curve(), ctx);
    // 广告平台
    auto start_platform = std::chrono::high_resolution_clock::now(); // 记录开始时间
    Platform platform(&w1, user_count_advertiser, user_count_platform, user_id_platform);
    // 验证广告主的证明
    bool result_batch = platform.proof_verify(proof_batch, ctx);
    auto end_platform = std::chrono::high_resolution_clock::now();                                                       // 记录结束时间
    auto duration_platform_batch = std::chrono::duration_cast<std::chrono::microseconds>(end_platform - start_platform); // 计算运行时间
    // 释放内存
    delete proof_batch;

    platform.round_P1(ctx);
    Message_P1 *message_p1 = platform.get_message_p1();

    if (advertiser.round_A2(message_p1, ctx))
    {
        std::cout << "round_A2 failed" << std::endl;
    }
    Message_A2 *message_a2 = advertiser.get_message_a2();

    if (platform.round_P3(message_a2, ctx))
    {
        std::cout << "round_P3 failed" << std::endl;
    }
    Message_P3 *message_p3 = platform.get_message_p3();

    if (advertiser.round_A4(message_p3, ctx))
    {
        std::cout << "round_A4 failed" << std::endl;
    }
    Message_A4 *message_a4 = advertiser.get_message_a4();

    if (platform.round_P5(message_a4, ctx))
    {
        std::cout << "round_P5 failed" << std::endl;
    }

    // 以JSON格式输出结果
    {
        float time_scale = 1000.0f * 1000.0f; // 时间单位换算
        float size_scale = 1024.0f;           // 尺寸单位换算
        std::cout << "{";
        // 批量验证结果
        std::cout << "\"input_size\": " << user_count_advertiser << ", "; // 用户数量
        if (result_batch)
        {
            std::cout << "\"result_batch\": true, "; // 验证成功
        }
        else
        {
            std::cout << "\"result_batch\": false, "; // 验证失败
        }
        // 输出一个data对象，其中包括time对象和size对象
        std::cout << "\"data\": {";
        // time对象里包含用户时间、广告主时间和广告平台时间
        // 设置输出精度
        std::cout << std::fixed << std::setprecision(6);
        std::cout << "\"time\": {";
        std::cout << "\"user\": " << duration_user.count() / time_scale << ", ";                         // 用户时间
        std::cout << "\"advertiser_batch\": " << duration_advertiser_batch.count() / time_scale << ", "; // 批量模式广告主时间
        std::cout << "\"platform_batch\": " << duration_platform_batch.count() / time_scale << ", ";     // 批量模式广告平台时间
        std::cout << "},";
        // size对象里包含证明尺寸
        // 设置输出精度
        std::cout << std::fixed << std::setprecision(3);
        std::cout << "\"size\": {";
        std::cout << "\"evidence\": " << evidence_size / size_scale << ", ";       // 证据尺寸
        std::cout << "\"proof_batch\": " << proof_size_batch / size_scale << ", "; // 批量模式证明尺寸
        std::cout << "}";
        std::cout << "}";
        std::cout << "}" << std::endl;
    }
    return 0;
}

// int test_verify(int user_count)
// {
//     // 初始化 OpenSSL
//     OpenSSL_add_all_algorithms();
//     BN_CTX *ctx = BN_CTX_new();

//     /* Global */
//     W1 w1(ctx); // 公共参数

//     Advertiser advertiser(&w1, user_count);

//     /* User */
//     // 存储所有用户的数据
//     User_data **user_data = new User_data *[user_count];             // 所有用户的数据
//     User_evidence **user_evidence = new User_evidence *[user_count]; // 所有用户的证据
//     size_t evidence_size = 0;                                        // 用户证据大小
//     std::chrono::microseconds duration_user(0);                      // 用户生成时间
//     // 循环生成用户数据

//     // 循环生成用户数据
//     // 并行化
// #pragma omp parallel for
//     for (int i = 0; i < user_count; i++)
//     {
//         // 生成随机用户
//         BN_CTX *ctx_user = BN_CTX_new();
//         User user(&w1);
//         auto start_user = std::chrono::high_resolution_clock::now(); // 记录开始时间
//         // 计算Ui和Vi
//         user.compute(ctx_user);
//         auto end_user = std::chrono::high_resolution_clock::now();                                     // 记录结束时间
//         duration_user += std::chrono::duration_cast<std::chrono::microseconds>(end_user - start_user); // 累加运行时间
//         // 存储用户数据
//         user_data[i] = user.get_user_data();
//         user_evidence[i] = user.get_user_evidence();
//         // 累加证据大小
//         evidence_size += user.get_evidence_size(ctx_user);
//         // 释放内存
//         BN_CTX_free(ctx_user);
//     }

//     // 计算用户时间的平均值
//     duration_user /= user_count;
//     // 计算证据的平均大小
//     evidence_size /= user_count;

//     /* 批量模式测试 */
//     // 广告主
//     auto start_advertiser = std::chrono::high_resolution_clock::now(); // 记录开始时间
//     advertiser.set_user_data(user_data);
//     // 计算广告主的证明
//     advertiser.proof_gen(ctx);
//     auto end_advertiser = std::chrono::high_resolution_clock::now();                                                           // 记录结束时间
//     auto duration_advertiser_batch = std::chrono::duration_cast<std::chrono::microseconds>(end_advertiser - start_advertiser); // 计算运行时间
//     // 获取证明
//     Proof *proof_batch = new Proof(w1.get_curve(), advertiser.get_proof());
//     // 计算证明的尺寸
//     size_t proof_size_batch = proof_batch->get_proof_size(user_count, w1.get_curve(), ctx);
//     // 广告平台
//     auto start_platform = std::chrono::high_resolution_clock::now(); // 记录开始时间
//     Platform platform(&w1, user_count, proof_batch);
//     // 验证广告主的证明
//     bool result_batch = platform.proof_verify(ctx);
//     auto end_platform = std::chrono::high_resolution_clock::now();                                                       // 记录结束时间
//     auto duration_platform_batch = std::chrono::duration_cast<std::chrono::microseconds>(end_platform - start_platform); // 计算运行时间
//     // 释放内存
//     delete proof_batch;

//     /* 单个模式测试 */
//     // 验证结果
//     bool result_single = true;
//     std::chrono::microseconds duration_advertiser_single(0); // 广告主生成时间
//     std::chrono::microseconds duration_platform_single(0);   // 广告平台验证时间
//     size_t proof_size_single = 0;                            // 证明的尺寸
//     for (int i = 0; i < user_count; i++)
//     {
//         // 广告主
//         User_data **user_data_temp = new User_data *[1];
//         user_data_temp[0] = new User_data(user_data[i]);
//         Advertiser advertiser_single(&w1, 1);
//         advertiser_single.set_user_data(user_data_temp);
//         auto start_advertiser_single = std::chrono::high_resolution_clock::now(); // 记录广告主开始时间
//         // 计算广告主的证明
//         advertiser_single.proof_gen(ctx);
//         auto end_advertiser_single = std::chrono::high_resolution_clock::now(); // 记录广告主结束时间
//         // 获取证明
//         Proof *proof_single = new Proof(w1.get_curve(), advertiser_single.get_proof());
//         // 累加证明的尺寸
//         proof_size_single += proof_single->get_proof_size(1, w1.get_curve(), ctx);
//         // 广告平台
//         Platform platform_single(&w1, 1, proof_single);
//         auto start_platform_single = std::chrono::high_resolution_clock::now(); // 记录广告平台开始时间
//         // 验证广告主的证明
//         bool result_temp = platform_single.proof_verify(ctx);
//         auto end_platform_single = std::chrono::high_resolution_clock::now(); // 记录广告平台结束时间
//         result_single &= result_temp;
//         // 累加广告主和广告平台的时间
//         duration_advertiser_single += std::chrono::duration_cast<std::chrono::microseconds>(end_advertiser_single - start_advertiser_single);
//         duration_platform_single += std::chrono::duration_cast<std::chrono::microseconds>(end_platform_single - start_platform_single);
//         // 释放内存
//         delete user_data_temp[0];
//         delete[] user_data_temp;
//         delete proof_single;
//     }

//     // 释放内存
//     for (int i = 0; i < user_count; i++)
//     {
//         delete user_data[i];
//         delete user_evidence[i];
//     }
//     delete[] user_data;
//     delete[] user_evidence;
//     // 释放上下文
//     BN_CTX_free(ctx);

//     // 以JSON格式输出结果
//     {
//         float time_scale = 1000.0f * 1000.0f; // 时间单位换算
//         float size_scale = 1024.0f;           // 尺寸单位换算
//         std::cout << "{";
//         // 批量验证结果
//         std::cout << "\"input_size\": " << user_count << ","; // 用户数量
//         if (result_batch)
//         {
//             std::cout << "\"result_batch\": true,"; // 验证成功
//         }
//         else
//         {
//             std::cout << "\"result_batch\": false,"; // 验证失败
//         }
//         // 单个验证结果
//         if (result_single)
//         {
//             std::cout << "\"result_single\": true,"; // 验证成功
//         }
//         else
//         {
//             std::cout << "\"result_single\": false,"; // 验证失败
//         }
//         // 输出一个data对象，其中包括time对象和size对象
//         std::cout << "\"data\": {";
//         // time对象里包含用户时间、广告主时间和广告平台时间
//         // 设置输出精度
//         std::cout << std::fixed << std::setprecision(6);
//         std::cout << "\"time\": {";
//         std::cout << "\"user\": " << duration_user.count() / time_scale << ",";                           // 用户时间
//         std::cout << "\"advertiser_batch\": " << duration_advertiser_batch.count() / time_scale << ",";   // 批量模式广告主时间
//         std::cout << "\"platform_batch\": " << duration_platform_batch.count() / time_scale << ",";       // 批量模式广告平台时间
//         std::cout << "\"advertiser_single\": " << duration_advertiser_single.count() / time_scale << ","; // 单个模式广告主时间
//         std::cout << "\"platform_single\": " << duration_platform_single.count() / time_scale << "";      // 单个模式广告平台时间
//         std::cout << "},";
//         // size对象里包含证明尺寸
//         // 设置输出精度
//         std::cout << std::fixed << std::setprecision(3);
//         std::cout << "\"size\": {";
//         std::cout << "\"evidence\": " << evidence_size / size_scale << ",";        // 证据尺寸
//         std::cout << "\"proof_batch\": " << proof_size_batch / size_scale << ",";  // 批量模式证明尺寸
//         std::cout << "\"proof_single\": " << proof_size_single / size_scale << ""; // 单个模式证明尺寸
//         std::cout << "}";
//         std::cout << "}";
//         std::cout << "}" << std::endl;
//     }
//     return 0;
// }
