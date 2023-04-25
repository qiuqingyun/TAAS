# 执行build/bin/main，并解析json输出

# 设置数组变量input_size为1 2 2^10 2^12 2^16 2^20
# input_size=(1 1024 4096 16384 65536 262144 1048576)
input_size=(4194304 16777216)
# input_size=(1 2 4 8 16)
# input_size=(1)

# 循环遍历数组，并作为main的参数
for i in ${input_size[@]}
do
    ../build/bin/main $i | jq .
    # 执行main，并将输出结果保存到变量result
    # result=$(../build/bin/main $i)
    # 使用jq解析result，并输出打印data.time.user，data.time.advertiser_batch
    # echo "== $i =="
    # echo $result | jq .data.time.user
    # echo $result | jq .data.time.advertiser_batch
    # echo $result | jq .data.time.platform_batch
    # echo $result | jq .data.time.advertiser_single
    # echo $result | jq .data.time.platform_single
    # echo $result | jq .data.size.evidence
    # echo $result | jq .data.size.proof_batch
    # echo $result | jq .data.size.proof_single
    # echo 
done