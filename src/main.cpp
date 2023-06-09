#include "User.h"
#include "Advertiser.h"
#include "Platform.h"
#include "ElGamal.h"
#include "hash.h"

int test_verify(int user_count);

int main(int argc, char *argv[])
{
    int thread_count = 0;          // 线程数
    int user_count_advertiser = 2; // 广告主的用户数量
    if (argc > 2)
        thread_count = atoi(argv[2]); // 读取argv[2]并赋值到thread_count
    if (argc > 1)
        user_count_advertiser = atoi(argv[1]); // 读取argv[1]并赋值到user_count

    // 设置线程数
    if (thread_count > 0)
        omp_set_num_threads(thread_count);

    int user_count_platform = std::ceil(user_count_advertiser * 1.0);     // 广告平台的用户数量
    int user_count_intersection = std::ceil(user_count_advertiser * 0.8); // 交集用户数量

    // 初始化 OpenSSL
    OpenSSL_add_all_algorithms();
    BN_CTX *ctx = BN_CTX_new();
    std::random_device rd;
    unsigned char seed[256];
    for (size_t i = 0; i < sizeof(seed); ++i)
    {
        seed[i] = static_cast<unsigned char>(rd());
    }
    RAND_seed(seed, sizeof(seed));

    /* Global */
    W1 w1(ctx); // 公共参数

    Advertiser advertiser(&w1, user_count_advertiser, user_count_platform);

    /* User */
    // 用户数据
    User_data **user_datas = new User_data *[user_count_advertiser];             // 用户数据，包括u,r和v
    std::string *user_datas_advertiser = new std::string[user_count_advertiser]; // 广告主拥有的用户数据，包括u和r
    BIGNUM **user_id_platform = new BIGNUM *[user_count_platform];               // 广告平台拥有的用户身份标识
    // 随机生成用户数据
    BIGNUM *Sum = BN_new(); // 累加user_data_advertiser[i]->v作为Sum
    BN_zero(Sum);
    for (int i = 0; i < user_count_intersection; ++i)
    {
        user_datas[i] = new User_data();
        user_datas[i]->u = BN_rand(256);
        user_datas[i]->r = BN_rand(256);
        user_datas[i]->v = BN_rand(16);
        user_id_platform[i] = BN_dup(user_datas[i]->u);
        BN_mod_add(Sum, Sum, user_datas[i]->v, w1.get_order(), ctx);
    }
    // 继续生成剩余的用户数据
    for (int i = user_count_intersection; i < user_count_advertiser; ++i)
    {
        user_datas[i] = new User_data();
        user_datas[i]->u = BN_rand(256);
        user_datas[i]->r = BN_rand(256);
        user_datas[i]->v = BN_rand(16);
    }
    for (int i = user_count_intersection; i < user_count_platform; ++i)
    {
        user_id_platform[i] = BN_rand(256);
    }

    // debug: 计算Sum*Ga
    EC_POINT *Sum_d = EC_POINT_new(w1.get_curve());
    EC_POINT_mul(w1.get_curve(), Sum_d, NULL, w1.get_Ga(), Sum, ctx);
    advertiser.debug_set_Sum_d(Sum_d);

    // 使用std::shuffle将user_id_platform进行随机排序
    std::shuffle(user_id_platform, user_id_platform + user_count_platform, std::default_random_engine(rd()));
    // 使用std::shuffle将user_data_advertiser进行随机排序
    std::shuffle(user_datas, user_datas + user_count_advertiser, std::default_random_engine(rd()));

    std::unordered_map<std::string, std::string> *U_Evidence = new std::unordered_map<std::string, std::string>(); // 使用一个map存储所有用户的证据
    size_t evidence_size = 0;                                                                                      // 用户证据大小
    std::chrono::microseconds duration_user(0);                                                                    // 用户生成时间
    // 生成用户数据
// 并行化
#pragma omp parallel for
    for (int i = 0; i < user_count_advertiser; i++)
    {
        // 生成随机用户
        BN_CTX *ctx_user = BN_CTX_new();
        User user(&w1, user_datas[i]->u, user_datas[i]->r, user_datas[i]->v);
        auto start_user = std::chrono::high_resolution_clock::now(); // 记录开始时间
        // 计算Ui和Vi
        user.compute(ctx_user);
        auto end_user = std::chrono::high_resolution_clock::now();                                     // 记录结束时间
        duration_user += std::chrono::duration_cast<std::chrono::microseconds>(end_user - start_user); // 累加运行时间
        // 获取msg_user_evidence
        std::string msg_user_evidence = user.get_msg_user_evidence(ctx_user);
        // 保存user_datas_advertiser
        user_datas_advertiser[i] = user.get_msg_user_data();
        std::string Ui_str = user.get_U(ctx_user);

#pragma omp critical
        // 将用户证据存入U_Evidence
        U_Evidence->insert(std::make_pair(
            Ui_str,
            msg_user_evidence));
#pragma omp atomic
        evidence_size += msg_user_evidence.size();
        // 释放内存
        BN_CTX_free(ctx_user);
    }
    // 计算用户时间的平均值
    duration_user /= user_count_advertiser;
    // 计算证据的平均大小
    evidence_size /= user_count_advertiser;
    // 循环释放user_datas
    for (int i = 0; i < user_count_advertiser; i++)
    {
        delete user_datas[i];
    }
    delete[] user_datas;

    // 广告主
    auto start_advertiser = std::chrono::high_resolution_clock::now(); // 记录开始时间
    advertiser.set_user_datas(user_datas_advertiser);
    advertiser.set_U_Evidence(U_Evidence);
    // 计算广告主的证明
    advertiser.proof_gen(ctx);
    auto end_advertiser = std::chrono::high_resolution_clock::now();                                                           // 记录结束时间
    auto duration_advertiser_batch = std::chrono::duration_cast<std::chrono::microseconds>(end_advertiser - start_advertiser); // 计算运行时间
    // 获取证明
    std::string proof_batch = advertiser.get_proof(ctx);
    // 计算证明的尺寸
    size_t proof_size_batch = proof_batch.size();
    // 广告平台
    auto start_platform = std::chrono::high_resolution_clock::now(); // 记录开始时间
    Platform platform(&w1, user_count_advertiser, user_count_platform, user_id_platform);
    // 验证广告主的证明
    platform.set_proof(proof_batch, ctx);
    bool result_batch = platform.proof_verify(ctx);
    if (!result_batch)
    {
        std::cout << "proof verify failed" << std::endl;
        return 1;
    }

    auto end_platform = std::chrono::high_resolution_clock::now();                                                       // 记录结束时间
    auto duration_platform_batch = std::chrono::duration_cast<std::chrono::microseconds>(end_platform - start_platform); // 计算运行时间

    auto start_platform_A1 = std::chrono::high_resolution_clock::now(); // 记录开始时间
    platform.round_P1(ctx);
    auto end_platform_A1 = std::chrono::high_resolution_clock::now();                                                       // 记录结束时间
    auto duration_platform_A1 = std::chrono::duration_cast<std::chrono::microseconds>(end_platform_A1 - start_platform_A1); // 计算运行时间
    std::string message_p1 = platform.get_message_p1(ctx);

    advertiser.set_message_p1(message_p1, ctx);
    auto start_advertiser_A2 = std::chrono::high_resolution_clock::now(); // 记录开始时间
    if (advertiser.round_A2(ctx))
    {
        std::cout << "round_A2 verify failed" << std::endl;
        return 1;
    }
    auto end_advertiser_A2 = std::chrono::high_resolution_clock::now();                                                           // 记录结束时间
    auto duration_advertiser_A2 = std::chrono::duration_cast<std::chrono::microseconds>(end_advertiser_A2 - start_advertiser_A2); // 计算运行时间
    std::string message_a2 = advertiser.get_message_a2(ctx);

    platform.set_message_a2(message_a2, ctx);
    auto start_platform_P3 = std::chrono::high_resolution_clock::now(); // 记录开始时间
    if (platform.round_P3(ctx))
    {
        std::cout << "round_P3 verify failed" << std::endl;
        return 1;
    }
    auto end_platform_P3 = std::chrono::high_resolution_clock::now();                                                       // 记录结束时间
    auto duration_platform_P3 = std::chrono::duration_cast<std::chrono::microseconds>(end_platform_P3 - start_platform_P3); // 计算运行时间
    std::string message_p3 = platform.get_message_p3(ctx);

    advertiser.set_message_p3(message_p3, ctx);
    auto start_advertiser_A4 = std::chrono::high_resolution_clock::now(); // 记录开始时间
    if (advertiser.round_A4(ctx))
    {
        std::cout << "round_A4 verify failed" << std::endl;
        return 1;
    }
    auto end_advertiser_A4 = std::chrono::high_resolution_clock::now();                                                           // 记录结束时间
    auto duration_advertiser_A4 = std::chrono::duration_cast<std::chrono::microseconds>(end_advertiser_A4 - start_advertiser_A4); // 计算运行时间
    std::string message_a4 = advertiser.get_message_a4(ctx);

    platform.set_message_a4(message_a4, ctx);
    auto start_platform_P5 = std::chrono::high_resolution_clock::now(); // 记录开始时间
    if (platform.round_P5(ctx))
    {
        std::cout << "round_P5 verify failed" << std::endl;
        return 1;
    }
    auto end_platform_P5 = std::chrono::high_resolution_clock::now();                                                       // 记录结束时间
    auto duration_platform_P5 = std::chrono::duration_cast<std::chrono::microseconds>(end_platform_P5 - start_platform_P5); // 计算运行时间
    // psi的总时间
    auto duration_psi = duration_platform_A1 + duration_advertiser_A2 + duration_platform_P3 + duration_advertiser_A4 + duration_platform_P5;
    // 计算消息的尺寸
    size_t message_p1_size = message_p1.size();
    size_t message_a2_size = message_a2.size();
    size_t message_p3_size = message_p3.size();
    size_t message_a4_size = message_a4.size();
    // 消息的总尺寸
    size_t message_size = message_p1_size + message_a2_size + message_p3_size + message_a4_size;

    // 释放内存
    for (int i = 0; i < user_count_platform; i++)
    {
        BN_free(user_id_platform[i]);
    }
    delete[] user_id_platform;
    delete[] user_datas_advertiser;
    delete U_Evidence;
    BN_free(Sum);
    EC_POINT_free(Sum_d);
    BN_CTX_free(ctx);

    // 以JSON格式输出结果
    {
        float time_scale = 1000.0f * 1000.0f; // 时间单位换算
        float size_scale = 1024.0f;           // 尺寸单位换算
        std::cout << "{";
        std::cout << "\"input_size\": " << user_count_advertiser << ", "; // 用户数量
        // 输出一个data对象，其中包括time对象和size对象
        std::cout << "\"data\": {";
        // time对象里包含用户时间、广告主时间和广告平台时间
        // 设置输出精度
        std::cout << std::fixed << std::setprecision(6);
        std::cout << "\"time\": {";
        std::cout << "\"evidence_gen\": " << duration_user.count() / time_scale << ", ";           // 用户生成证据时间
        std::cout << "\"prove_gen\": " << duration_advertiser_batch.count() / time_scale << ", ";  // 广告主生成证明时间
        std::cout << "\"prove_verify\": " << duration_platform_batch.count() / time_scale << ", "; // 广告平台验证证明时间
        std::cout << "\"psi\": " << duration_psi.count() / time_scale << ", ";                     // psi总时间
        std::cout << "\"psi_P1\": " << duration_platform_A1.count() / time_scale << ", ";          // psi_P1时间
        std::cout << "\"psi_A2\": " << duration_advertiser_A2.count() / time_scale << ", ";        // psi_A2时间
        std::cout << "\"psi_P3\": " << duration_platform_P3.count() / time_scale << ", ";          // psi_P3时间
        std::cout << "\"psi_A4\": " << duration_advertiser_A4.count() / time_scale << ", ";        // psi_A4时间
        std::cout << "\"psi_P5\": " << duration_platform_P5.count() / time_scale << " ";           // psi_P5时间
        std::cout << "},";
        // size对象里包含证明尺寸
        // 设置输出精度
        std::cout << std::fixed << std::setprecision(3);
        std::cout << "\"size\": {";
        std::cout << "\"evidence\": " << evidence_size / size_scale << ", "; // 证据尺寸
        std::cout << "\"proof\": " << proof_size_batch / size_scale << ", "; // 证明尺寸
        std::cout << "\"psi\": " << message_size / size_scale << ", ";       // psi总尺寸
        std::cout << "\"psi_P1\": " << message_p1_size / size_scale << ", "; // psi_P1消息尺寸
        std::cout << "\"psi_A2\": " << message_a2_size / size_scale << ", "; // psi_A2消息尺寸
        std::cout << "\"psi_P3\": " << message_p3_size / size_scale << ", "; // psi_P3消息尺寸
        std::cout << "\"psi_A4\": " << message_a4_size / size_scale << " ";  // psi_A4消息尺寸
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
//     size_t proof_size_batch = proof_batch->get_size(user_count, w1.get_curve(), ctx);
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
//         proof_size_single += proof_single->get_size(1, w1.get_curve(), ctx);
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
