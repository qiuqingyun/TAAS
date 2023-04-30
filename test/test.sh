# 执行build/bin/main，并解析json输出

# 设置数组变量input_size为2^0 2^10 2^12 2^14 2^16 2^18 2^20 2^22 2^24
# input_size=(1 1024 4096 16384 65536 262144 1048576 4194304 16777216)
# 设置数组变量input_size为2^0 2^10 2^12 2^14 2^16 2^18 2^20
input_size=(1 1024 4096 16384 65536 262144 1048576)
# input_size=(4194304 16777216)
# input_size=(1 2 4 8 16)
# input_size=(1)

# 删除result.log
rm -rf ./result.log

# 循环遍历数组，并作为main的参数
for i in ${input_size[@]}
do
    # 执行main，并将输出结果保存到变量result
    result=$(../build/bin/main $i)
    # 使用jq解析result，并输出打印
    input_size=$(echo $result | jq .input_size)
    evidence_gen=$(echo $result | jq .data.time.evidence_gen)
    prove_gen=$(echo $result | jq .data.time.prove_gen)
    prove_verify=$(echo $result | jq .data.time.prove_verify)
    psi_time=$(echo $result | jq .data.time.psi)
    evidence=$(echo $result | jq .data.size.evidence)
    proof=$(echo $result | jq .data.size.proof)
    psi_size=$(echo $result | jq .data.size.psi)
    echo -e "$input_size\n$evidence_gen\n$prove_gen\n$prove_verify\n$psi_time\n$evidence\n$proof\n$psi_size\n" >> ./result.log
done