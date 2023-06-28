# 验证

## 公共参数

1. 一个模为 $q$ 的有限循环群 $G$ ，以及上面的点 $(G_0,G_1,G_2,H_0,G_a,H_a)$ 。

2. 广告主的同态加密公钥 $pk_A=sk_A \cdot H_a$。
3. 公共参数  $W_1=(G_0,G_1,G_2,H_0,G_a,H_a,q,pk_A)$ 。

## $U_i$ 的操作

- 输入：身份标识 $u_i$，金额 $v_i$。
- 计算：
  1. 选择随机数 $r_i$。
  2. 计算 $U_i={u_i}\cdot G_0 + {r_i} \cdot H_0$。
  3. 计算 $V_i=Enc(pk_A,v_i)=(v_i\cdot G_a+r_i^\prime\cdot pk_A,r_i^\prime\cdot H_a)$。
- 输出：公开 $(U_i,V_i)$，并将 $(u_i,r_i)$ 发送给$A$ 。

## $A$ 的操作

- 输入： $\{(u_i,r_i)\}_{i\in[1,n]}$ 
- 计算：
  1. **选择**随机数 $k_1$，$k^\prime$，$x^\prime$ 和 $y^\prime$。
  2. **选择** $n$ 个随机数 $\{a_1,a_2,...,a_n\}$。
  3. 设置 $U^\prime=0$。
  4. 设置 $\hat x=x^\prime$。
  5. 设置 $\hat y=y^\prime$。
  6. 对于 $i\in[1,n]$ ：
     1. 计算 $U_i={u_i}\cdot G_0+{r_i}\cdot H_0$。
     2. 计算 $A_i={k_1}\cdot (u_i\cdot G_2)$。
     3. 计算 $D_i={k_1}\cdot U_i$。
     4. **设置** $P_i=(A_i,D_i)$。
     5. 计算 $S_i=\text H(i\|W_1\|P_i)$。
     6. 计算 $U^\prime=U^\prime+ {a_i}\cdot U_i$。
     7. 计算 $\hat x=\hat x+S_ik_1u_i$。
     8. 计算 $\hat y=\hat y+S_ik_1r_i$。
  7. 计算 $W={k_1}\cdot G_1$。
  8. 计算 $W^\prime={k^\prime}\cdot G_1$。
  9. 计算 $C_1={k_1}\cdot U^\prime$。
  10. 计算 $C_1^\prime={k^\prime}\cdot U^\prime$。
  11. 计算 $A^\prime={x^\prime}\cdot G_2$。
  12. 计算 $D^\prime={x^\prime}\cdot G_0 + {y^\prime}\cdot H_0$。
  13. **设置** $P_0=(W^\prime,C_1^\prime)$。
  14. 计算 $S_0=\text H(W_1\|P_0)$。
  15. 计算 $\hat k=S_0k_1+k^\prime$。
- 输出：公开 $(W,W^\prime,C_1,C_1^\prime,U^\prime,A^\prime,D^\prime,\hat k,\hat x,\hat y)$ 和 $\{(U_i,A_i,D_i)\}_{i\in[1,n]}$。

## $P$ 的操作

- 输入： $(W,W^\prime,C_1,C_1^\prime,U^\prime,A^\prime,D^\prime,\hat k,\hat x,\hat y)$ 和 $\{(U_i,A_i,D_i)\}_{i\in[1,n]}$。
- 计算：
  1. **设置** $P_0=(W^\prime,C_1^\prime)$。
  2. 计算 $S_0=\text H(W_1\|P_0)$。
  3. **验证** ${\hat k}\cdot G_1={S_0}\cdot W+W^\prime$。
  4. **验证** ${\hat k}\cdot U^\prime={S_0}\cdot C_1 +C_1^\prime$。
  5. **设置** $P_i=(A_i,D_i)$，其中 $i\in[1,n]$ 。
  6. 计算 $S_i=\text H(i\|W_1\|P_i)$，其中 $i\in[1,n]$ 。
  7. **验证** ${\hat x}\cdot G_2=\sum^n_{i=1} {S_i}\cdot A_i+ A^\prime$。
  8. **验证** ${\hat x}\cdot G_0+{\hat y}\cdot H_0=\sum^n_{i=1} {S_i}\cdot D_i+D^\prime$。
- 输出：验证的结果

## 测试

1. 单个和批量的对比

# PSI

## P1的操作

- 输入：身份标识 $\{W_j\}_{j\in[1,m]}$
- 计算：

1. 选择随机数 $k_2$，$k_3$ 和 $Z'$
2. 计算 $P'=Z'\cdot G_2$
3. 设置 $\hat Z=Z'$
4. 对于 $j\in[1,m]$ ：
   1. 计算 $P_j=k_3\cdot W_j\cdot G_2$
   2. 计算 $t_j=H(j||W_1||P')$
   3. 计算 $\hat Z=\hat Z+t_j\cdot k_3\cdot W_j$

- 输出：$\{P_j\}_{j\in[1,m]}$ 和 $(\hat Z,P')$

## A2的操作

- 输入：$\{P_j\}_{j\in[1,m]}$ 和 $(\hat Z,P')$
- 计算：
  1. 计算 $t_j=H(j||W_1||P')$，对于 $j\in[1,m]$ 
  2. 验证 $\hat Z\cdot G_2=\sum^m_{j=1}t_j\cdot P_j+P'$
  3. 选择 $m$ 个随机数 $\{r'_1,r'_2,...,r'_m\}$
  4. 选择 $m$ 个随机数 $\{\rho_1,\rho_2,...,\rho_m\}$
  5. 选择 $m$ 个随机数 $\{s_1,s_2,...,s_m\}$
  6. 选择 $m$ 个随机数 $\{t_1,t_2,...,t_m\}$
  7. 选择 $m$ 个随机数 $\{x'_1,x'_2,...,x'_m\}$
  8. 选择 $m$ 个随机数 $\{y'_1,y'_2,...,y'_m\}$
  9. 选择随机数 $sk'_A$
  10. 选择一个包含整数 $[1,m]$ 的数组 $\pi$ ，并将其洗牌
  11. 对于 $j\in[1,m]$ ：
      1. 计算 $C_j=(k_1\cdot P_j+r'_j\cdot pk_A,r'_j\cdot H_a)$
      2. 计算 ${C'_1}_j=x'_j\cdot P_j+y'_j\cdot pk_A$ 
      3. 计算 ${C'_2}_j=y'_j\cdot H_a$ 
      4. 计算 $S_j=H(W_1||{C'_1}_j||{C'_2}_j)$ 
      5. 计算 $\hat{x'}_j=S_j\cdot k_1+x'_j$
      6. 计算 $\hat{y}_j=S_j\cdot r'_j+y'_j$
  12. 对于 $j\in[1,m]$ ：
      1. 计算 $C'_j=(\rho_j\cdot pk_A,\rho_j\cdot H_a)+C_{\pi_j}$
      2. 计算 $C_{A_j}=\pi_j\cdot G_2+s_j\cdot H_a$
  13. 计算 $x=H(W_1||C_{A_1})$
  14. 对于 $j\in[1,m]$ ：
      1. 计算 $B_j=x^{\pi_j}$
      2. 计算 $C_{B_j}=B_j\cdot G_2+t_j\cdot H_a$
  15. 计算 $y=H(1||W_1||C_{B_1})$
  16. 计算 $z=H(2||W_1||C_{B_1})$
  17. 设置 $E=1$
  18. 对于 $j\in[1,m]$ ：
      1. 计算 $D'_j=B_j+y\cdot \pi_j-z$
      2. 计算 $C_{D'_j}=D'_j\cdot G_2+(y\cdot s_j+t_j)\cdot H_a$
      3. 计算 $E=E\cdot D'_j$
  19. 计算 $\rho'=-\sum^m_{j=1}\rho_j\cdot B_j$
  20. 计算 $F=(\rho'\cdot pk_A,\rho'\cdot H_a)+\sum^m_{j=1}B_j\cdot C'_j$
  21. 对于 $j\in[1,m]$ ：
      1. 计算 $Q_j={C_j}_1+({C_j}_2\cdot sk_A)^{-1}$
  22. 计算 $G_S=sk_A\cdot G_2$
  23. 计算 $G_S'=sk'_A\cdot G_2$
  24. 计算 $pk'_A=sk'_A\cdot H_a$
  25. 计算 $t_s=H(W_1||G'_S||pk'_A)$
  26. 计算 $\hat{sk_A}=t_s\cdot sk_A + sk'_A$
- 输出：$\{(C_j,C'_j)\}_{j\in[1,m]}$  ，$\{(C_{A_j},C_{B_j},C_{D'_j})\}_{j\in[1,m]}$，$\{A_i\}_{i\in[1,n]}$ ，标量$E$ 和密文 $F$，$\{Q_j\}_{j\in[1,m]}$，$(G_S,G'_S,pk'_A,\hat{sk_A})$，$\{({C'_1}_j,{C'_2}_j,\hat{x}_j,\hat{y}_j)\}_{j\in[1,m]}$

## P3的操作

- 输入：$\{(C_j,C'_j)\}_{j\in[1,m]}$ ，$\{(C_{A_j},C_{B_j},C_{D'_j})\}_{j\in[1,m]}$，$\{A_i\}_{i\in[1,n]}$ ，标量$E$ 和密文 $F$，$\{Q_j\}_{j\in[1,m]}$，$(G_S,G'_S,pk'_A,\hat{sk_A})$，$\{({C'_1}_j,{C'_2}_j,\hat{x}_j,\hat{y}_j)\}_{j\in[1,m]}$
- 计算：
  1. 计算 $x=H(W_1||C_{A_1})$
  2. 计算 $y=H(1||W_1||C_{B_1})$
  3. 计算 $z=H(2||W_1||C_{B_1})$
  4. 对于 $j\in[1,m]$ ：
     1. 计算 $C_{D_j}=y\cdot C_{A_j}+C_{B_j}-z\cdot G_2$
     2. 计算 $S_j=H(W_1||{C'_1}_j||{C'_2}_j)$
     3. 验证 $\hat{x}_j\cdot P_j+\hat{y}_j\cdot pk_A=S_j\cdot {C_1}_j+{C'_1}_j$ 
     4. 验证 $\hat{y}_j\cdot H_a=S_j\cdot {C_2}_j+{C'_2}_j$ 
  5. 验证向量 $C_{D'}=C_{D}$
  6. 验证 $E=\prod^m_{j=1}(x^j+y\cdot j-z)$
  7. 验证 $F=\sum^m_{j=1}C_j\cdot x^j$
  8. 计算 $t_s=H(W_1||G'_S||pk'_A)$
  9. 验证 $\hat{sk_A}\cdot G_2=t_s\cdot G_S+G_S'$
  10. 验证 $\hat{sk_A}\cdot H_a=t_s\cdot pk_A+pk'_A$
  11. 选择随机数 $k'_2$，$k'_q$
  12. 选择 $m$ 个随机数 $\{b_1,b_2,...,b_m\}$
  13. 选择 $n$ 个随机数 $\{c_1,c_2,...,c_n\}$
  14. 设置 $Q'=0$
  15. 对于 $j\in[1,m]$ ：
      1. 计算 $J_j=k_2\cdot Q_j$
      2. 计算 $Q'=Q'+b_j\cdot Q_j$
  16. 计算 $C_2=k_2\cdot Q'$
  17. 计算 $C'_2=k'_2\cdot Q'$
  18. 计算 $t_q=H(W_1||C'_2)$
  19. 计算 $\hat{k_2}=t_q\cdot k_2+k'_2$
  20. 设置 $A'=0$
  21. 对于 $i\in[1,n]$ ：
      1. 计算 $L_i=k_3\cdot k_2\cdot A_i$
      2. 计算 $A'=A'+c_i\cdot A_i$
  22. 计算 $k_q=k_3\cdot k_2$
  23. 计算 $C_3=k_q\cdot A'$
  24. 计算 $C'_3=k'_q\cdot A'$
  25. 计算 $t_a=H(W_1||C'_3)$
  26. 计算 $\hat{k_q}=t_a\cdot k_q+k'_q$
- 输出：$\{J_j\}_{j\in[1,m]}$，$\{L_i\}_{i\in[1,n]}$ 和 $(\hat{k_2},C_2,C'_2,C_3,C'_3,\hat{k_q},Q',A')$

## A4的操作

- 输入：$\{J_j\}_{j\in[1,m]}$，$\{L_i\}_{i\in[1,n]}$ 和 $(\hat{k_2},C_2,C'_2,C_3,C'_3,\hat{k_q},Q',A')$
- 计算：
  1. 计算 $t_q=H(W_1||C'_2)$
  2. 计算 $t_a=H(W_1||C'_3)$
  3. 验证 $\hat{k_2}\cdot Q'=t_q\cdot C_2+C'_2$
  4. 验证 $\hat{k_q}\cdot A'=t_a\cdot C_3+C'_3$
  5. 计算向量 $J$ 与向量 $L$ 的交集，并同态累加交集中的 $V_i$ 得到 $Sum_E$
  6. 解密 $Sum_E$ 得到 $Sum$
  7. 选择随机数 $sk''_A$
  8. 计算 $G_K=sk_A\cdot G_a$
  9. 计算 $G'_K=sk''_A\cdot G_a$
  10. 计算 $pk''_A=sk''_A\cdot H_a$
  11. 计算 $t_b=H(W_1||G'_K||pk''_A)$
  12. 计算 $\hat{sk'_A}=t_b\cdot sk_A+sk''_A$
- 输出： $Sum$，$(G_K,G'_K,pk''_A,\hat{sk'_A})$

## P5的操作

- 输入： $Sum$，$(G_K,G'_K,pk''_A,\hat{sk'_A})$
- 计算：
  1. 计算 $t_b=H(W_1||G'_K||pk''_A)$
  2. 验证 $\hat{sk'_A}\cdot G_a=t_b\cdot G_K+G'_K$
  3. 验证 $\hat{sk'_A}\cdot H_a=t_b\cdot pk_A+pk''_A$
- 输出：验证结果

## ElGamal

- 密钥生成：
  1. 私钥 $sk$
  2. 公钥 $pk=sk \cdot H$
- 加密：
  1. 选择随机数 $r$
  2. $C_1=m\cdot G+r\cdot pk$
  3. $C_2=r\cdot H$
  4. 密文 $(C_1,C_2)$
- 解密：
  1. $m\cdot G=C_1+(C_2\cdot sk)^{-1}$