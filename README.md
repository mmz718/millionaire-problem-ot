# Millionaires' Problem and Oblivious Transfer

Python 实现两种百万富翁比较协议：原始 RSA 公钥比较方案，以及 RSA 型 n 选 1 不经意传输（OT）比较方案。最终只输出 `Alice 更富有`、`Bob 更富有` 或 `双方财富相等`。

## 运行

需要 Python 3.10+。

```bash
python -m pip install -r requirements.txt
python main.py --alice 7 --bob 4 --domain 10 --scheme both
python main.py --alice 5 --bob 5 --domain 10 --scheme both
```

`--scheme original` 或 `--scheme ot` 可单独运行，`--metrics` 显示公共性能统计。默认 RSA 2048 位；财富必须属于公开整数域 `[1, domain]`。命令行同时输入双方财富仅用于本地模拟。

## 代码

- `crypto_utils.py`：RSA 密钥、压缩素数、密码随机采样、SHAKE256 掩码。
- `channel.py`：序列化通信，统计实际 UTF-8 JSON 字节及单向消息数。
- `protocols.py`：双方状态、原始比较、独立 OT 及 OT 比较。
- `main.py`：运行入口。
- `test_protocols.py`、`run_validation.py`：功能和边界测试、保存测试记录。
- `verify_cli.py`：验证三种比较结果、独立 OT 统计输出和非法输入处理。
- `benchmark.py`：相同输入下的性能与正确性测量。
- `results/`：测试记录与实测 CSV、JSON。

协调器只传递消息，不读取双方秘密直接比较。明文标准答案仅由协议外测试驱动使用。原始方案交换角色两次判断以区分相等；OT 让 Bob 秘密读取 Alice 本地比较结果表的一个表项，直接得到三态结果。

## 验证与复现

```bash
python run_validation.py
python verify_cli.py
python benchmark.py
```

单元测试共 19 个方法，包含 M=5 的 25 对输入穷举，两套协议共 50 次执行；另覆盖重复、相等、极值、M=1、模运算回绕、环形间距、失败重试与耗尽、任意字节 OT、会话绑定与复用。穷举使用 subTest，不额外计入方法数。

随附性能数据使用 RSA 2048 位、压缩素数 1024 位、SHAKE256，在 Windows 11 / Python 3.12.14 / cryptography 50.0.1 下测量。M=5 穷举 25 对，M=10 和 25 各 15 对；共 55 对输入、110 次完整比较，正确率均为 100%，无失败。最大、最小、中位和平均耗时及通信量见 `results/benchmark.json`。

在线时间包括完整三态比较、新压缩素数生成、消息构造、编码及结果公开，长期密钥生成单独记录。通信量包括公钥、JSON 信封和结果，不含 TCP/TLS 报头。一次单方向消息计一轮：原始方案 8 轮，OT 比较 4 轮。每个输入域独立预热，配对顺序交替。公开测试输入固定种子，协议秘密仍使用密码随机源。重新测量会覆盖结果，耗时会波动。

## 安全条件

本项目是半诚实模型下的教学实现。保护范围为一次协议输出以外的额外信息；相等结果和重复合法比较可能带来必然推论。没有恶意安全、传输认证、常数时间私钥运算或宿主内存隔离。

原始压缩方案依赖额外分布条件，RSA 单向性不能直接构成整个协议的安全证明。OT 使用上下文分离的哈希掩码，安全讨论依赖 RSA 求逆困难及随机预言机式哈希建模。不能用消息与逆像直接相加来保护低熵比较消息，否则可枚举消息后用公钥验证。正确性测试不等于密码学安全证明。

输入域按候选项枚举，两套方案都随域大小扩展，适用于小范围实验。本仓库仅包含代码、测试和验证结果。
