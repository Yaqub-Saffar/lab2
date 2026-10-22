# 第三方源码说明（SM2349）

本目录是**商用密码检测中心（SCCTC）SM2/SM3/SM4 参考实现源码**的快照，
用于本实验的编译、运行与交叉验证。本目录内容不是我写的，请勿在此基础上声称原创。

## 来源

| 项 | 值 |
| --- | --- |
| 官方发布页 | https://www.scctc.org.cn/xzzx/sfydm/ydmxz/ |
| 官方源码包（PDF 版） | `SM2算法源代码/`、`SM3算法源代码/`、`SM4算法源代码/`，见 `docs/01-源码获取与溯源.md` |
| 可编译镜像 | https://github.com/Arkq/SM2349 |
| 快照 commit | `3364e2a`（"Provide MIRACL library as a git submodule"） |
| 依赖库 | MIRACL Core（git submodule，commit `b9b8fd4`），**不随本仓库分发** |

## 为什么可以直接编译

官方包里**没有 `.c` / `.h` 文件**，源码是以 PDF 清单形式发布的
（`SM3_c文件.pdf`、`SM4_c文件.pdf`、`SM2_签名验签_c文件.pdf` 等）。
镜像仓库的 commit `816c400` 标题即为 **"Add source files extracted from PDFs"**，
即镜像源码就是官方 PDF 的抽取结果。

本实验不直接相信这条说明，而是做了**独立复核**：

1. 用 `scripts/pdf_text.py` 把官方 PDF 还原成文本（`artifacts/official/pdf-text/`）；
2. 用 `scripts/compare_pdf_code.py` 把本目录的 `.c` 逐行（去缩进、去注释后）
   去官方 PDF 文本里找；
3. 结果：**1420 行代码中 1353 行在官方 PDF 中逐字命中（95.3%）**
   （SM3.c 98.5%、SM4.c 96.7%、SM2_sv.c 93.3%、SM2_ENC.c 94.0%、SM2_KEY_EX.c 95.7%）。

未命中的少数行是 PDF 抽取时的换页/断字造成的，不代表代码有出入。

复核命令与原始输出见 `docs/01-源码获取与溯源.md`。

## 授权声明（来自上游 README，原文保留于 `UPSTREAM-README.md`）

> Every source code in this repository can be used for academic, non-profit
> making or non-commercial use only. All implementation are based on MIRACL
> Cryptographic SDK, which also requires a proper license which may be obtained
> from Shamus Software Ltd.

即：本仓库内容仅限学术、非营利、非商业用途；底层 MIRACL 库需另行获得授权。
本实验为课程范围内的教学验证，使用范围符合上述条款。

## 本目录与上游的差异

- 只保留 `src/`（`SM3.c` `SM4.c` `SM2_sv.c` `SM2_ENC.c` `SM2_KEY_EX.c` `ZUC.c`
  及头文件）、`Makefile`、上游 README；
- **不含** MIRACL 源码与 `miracl.a`（体积大且有独立许可），构建时按
  `docs/01-源码获取与溯源.md` 的步骤在 guest 内单独获取；
- 未修改上游任何一行代码。实验新增的验证程序在仓库根的 `tools/` 下。
