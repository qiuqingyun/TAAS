# 执行build/bin/main，并解析json输出

# 设置数组变量input_size为2^0 2^10 2^12 2^14 2^16 2^18 2^20 2^22 2^24
input_size=(1 1024 4096 16384 65536 262144 1048576 4194304 16777216)
# input_size=(4194304 16777216)
# input_size=(1 2 4 8 16)
# input_size=(1)

# 删除result.log
rm -rf ./result.log

# 循环遍历数组，并作为main的参数
for i in ${input_size[@]}
do
    # ../build/bin/main $i | jq . >> ./result.log
    # 执行main，并将输出结果保存到变量result
    result=$(../build/bin/main $i)
    # 使用jq解析result，并输出打印data.time.user，data.time.advertiser_batch
    user=$(echo $result | jq .data.time.user)
    advertiser_batch=$(echo $result | jq .data.time.advertiser_batch)
    platform_batch=$(echo $result | jq .data.time.platform_batch)
    advertiser_single=$(echo $result | jq .data.time.advertiser_single)
    platform_single=$(echo $result | jq .data.time.platform_single)
    evidence=$(echo $result | jq .data.size.evidence)
    proof_batch=$(echo $result | jq .data.size.proof_batch)
    proof_single=$(echo $result | jq .data.size.proof_single)
    echo -e "$i\n$user\n$advertiser_batch\n$platform_batch\n$advertiser_single\n$platform_single\n$evidence\n$proof_batch\n$proof_single\n" >> ./result.log
done