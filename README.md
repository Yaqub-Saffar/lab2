# 实验二 · 密码算法实现（1-3 学时）

**20241422 穆弈涵** · 《密码系统设计》

在 openEuler 24.03 上**编译运行商用密码检测中心（SCCTC）发布的 SM2/SM3/SM4 参考实现**，
用 **GmSSL 3.2.0 / OpenSSL 3.5.6 做双向交叉验证**，并把**代码与国家标准逐条对应**。

---

## 1. 任务对照

| # | 作业要求 | 完成 | 证据 |
| --- | --- | --- | --- |
| ① | 调试运行检测中心源代码，至少 SM2/SM3/SM4；用 GmSSL 验证正确性；Markdown 记录过程；每完成一项功能/函数 git commit 一次（14 分） | ✅ | [`实践过程.md`](实践过程.md)、`artifacts/verify_all-2026-10-22.txt`（25/25 PASS）、**17 次提交（其中 11 次为功能级提交）** |
| ② | 在密标委网站查找 SM2/SM3/SM4 标准，分析代码与标准的对应关系（6 分） | ✅ | [`docs/02`](docs/02-SM3实现与标准对应.md)~[`docs/04`](docs/04-SM2实现与标准对应.md)、`artifacts/gmbz-norm-list.json`（该站后台接口取回的全量 177 条原始 JSON；本轮未附浏览器界面截图，证据为 JSON + 自写筛选脚本） |
| ③ | Rust 实现（选做 10 分） | ⛔ 未做 | — |
| ④ | 提交仓库链接 + git log | 🟡 | git log 完整（本仓库 `main` 分支，18 次提交）；**GitHub 推送本轮按要求暂缓**——`github.com` 本机 TCP 连接被重置，`api.github.com` 可达；网络恢复后建仓 `Yaqub-Saffar/lab2` 直接 push |
| ⑤ | 提交实践过程 Markdown 与 PDF；代码文档托管；记录问题、解决过程、反思 | ✅ | `实践过程.md`（含 3 张实机运行截图）+ `实践过程.pdf`（13 页 / 3 图内嵌）；`docs/05` §5.2 记录了 10 个真实问题 |

## 2. 结论速览

- **正确性**：SM3 / SM4 / SM2（密钥生成、签名验签、公钥加解密）全部与国标附录 A 向量、
  GmSSL、OpenSSL **双向互验一致**；25 项断言 **25 PASS / 0 FAIL**；
  篡改消息、篡改 r、篡改 C3 三类负例均按预期失败。
- **溯源**：官方发布包内只有 PDF 清单；本实验把官方 PDF 抽成文本，
  镜像源码 **1420 行中 1353 行（95.3%）逐字命中**，证明编译运行的确实是检测中心那份代码。
- **标准对应**：曲线参数、ZA、签名 A1~A6、验签、加密 B1~B7、KDF、密文布局、
  SM3 填充/IV/压缩、SM4 密钥扩展/轮函数，逐条落到 `docs/02`~`docs/04`。

## 3. 目录

```
实验二/
├── README.md                ← 本文件
├── 实践过程.md / .pdf        ← 作业要求提交的过程记录
├── docs/
│   ├── 00-实验环境与构建流程.md
│   ├── 01-源码获取与溯源.md
│   ├── 02-SM3实现与标准对应.md
│   ├── 03-SM4实现与标准对应.md
│   ├── 04-SM2实现与标准对应.md
│   └── 05-交叉验证与结论.md    ← 问题/解决/反思
├── tools/                   验证驱动（本人写）
│   ├── drv_sm3.c            SM3 摘要
│   ├── drv_sm4.c            SM4 单块加解密
│   ├── drv_sm2_sv.c         SM2 密钥生成 / 签名 / 验签（自算 ZA）
│   ├── drv_sm2_enc.c        SM2 公钥加解密
│   └── sm2_der.c            SM2 签名与密文的 DER 编解码
├── scripts/
│   ├── guest.ps1            宿主↔虚机 SSH 通道（同步/执行/抓取）
│   ├── build_guest.sh       虚机内构建（-Dmain= 改写上游入口）
│   ├── verify_all.sh        25 项交叉验证
│   ├── gmssl_key_dump.py    解析 GmSSL 加密私钥（PBES2+PBKDF2-SM3+SM4-CBC）
│   ├── pdf_text.py          官方 PDF → 文本
│   └── compare_pdf_code.py  源码逐行回查官方 PDF（溯源）
├── third_party/SM2349/      检测中心源码快照 + NOTICE（授权声明）
└── artifacts/               真实日志：env / build / verify / PDF 文本 / 密标委列表
```

## 4. 快速复现

```bash
# 虚机内（openEuler 24.03）
git clone https://github.com/Arkq/SM2349.git
cd SM2349 && git submodule update --init --recursive
make miracl.a && make          # 上游 6 个自检程序，退出码 0 即通过
# 再按 docs/00-实验环境与构建流程.md 建 ~/exp2/our，放入 tools/ 与 scripts/
bash our/scripts/build_guest.sh   # 编译 5 个驱动
bash our/scripts/verify_all.sh    # 25 项交叉验证
```

## 5. 关键数据（实测）

| 项 | 值 |
| --- | --- |
| SM3(`abc`) | `66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0` |
| SM3(`abcd`×16) | `DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732` |
| SM4(A.1 向量) | `681EDF34D206965E86B3E94F536E4246` |
| SM2 A.2 公钥 xA | `09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020` |
| SM2 A.2 公钥 yA | `CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13` |
| ZA（GmSSL 密钥） | `E98824291A501B3D702DC3563CCA2D806AD18E06F54BA0E897DBEDA8C15DE60C` |

## 6. 授权说明

`third_party/SM2349/` 为检测中心发布源码的快照，仅限学术、非营利、非商业用途（见
`third_party/SM2349/UPSTREAM-README.md`、`NOTICE.md`）。底层 MIRACL 库需另行获得授权，
本仓库不包含 MIRACL。`tools/`、`scripts/`、`docs/` 为本人本实验新增内容。
