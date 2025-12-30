# JWT CLI

JWT命令行工具 - 解密、生成和爆破JWT令牌

## 更新日志

### v1.0.1 (2024-12-31)
**Bug 修复：**
- 修复 Windows PowerShell 解析 JSON 时键名引号丢失的问题
- 修复 Windows 换行符（CRLF）导致字典爆破失败的问题
- 修复 crack 命令强制要求字典文件的问题，现在支持使用内置字典
- sign 命令的 `-p` 参数现在支持从 `.json` 和 `.txt` 文件读取

**改进：**
- 所有平台统一使用单引号包裹 JSON 的用法
- 错误提示更加友好，明确区分 CMD、PowerShell 和 Linux/Mac 的用法
- 帮助信息更加清晰

### v1.0.0
- 初始版本

## 功能特性

- **decode** - 解密JWT并自动验证/爆破密钥（内置84个常见密码）
- **sign** - 生成JWT令牌
- **crack** - 使用字典爆破JWT密钥

## 安装

```bash
go build -o jwt_cli main.go jwt.go
```

## 快速开始

```bash
# 查看帮助
jwt_cli -h

# 解密JWT（自动使用内置字典爆破）
jwt_cli decode <token>

# 生成JWT
jwt_cli sign -p '{"sub":"user123"}'

# 爆破密钥
jwt_cli crack <token> -w wordlist.txt -t 8
```

## 命令说明

### decode - 解密JWT令牌

解密并显示JWT的Header、Payload，自动验证或爆破签名密钥。

```bash
jwt_cli decode [jwt_token] [选项]
```

**验证模式：**

| 模式 | 说明 | 命令 |
|------|------|------|
| 指定密钥 | 使用已知密钥验证签名 | `jwt_cli decode <token> -s mysecret` |
| 外部字典 | 使用字典文件爆破 | `jwt_cli decode <token> -w words.txt` |
| 内置字典 | 自动爆破（默认） | `jwt_cli decode <token>` |

**选项：**
- `-s <密钥>` - 验证签名的密钥
- `-w <文件>` - 密码字典文件
- `-t <线程数>` - 并发线程数（默认：4）

### sign - 生成JWT令牌

使用指定载荷和密钥生成JWT令牌。

```bash
jwt_cli sign [选项]
```

**选项：**
- `-p <json|文件>` - JWT载荷（必需），支持JSON字符串或.json/.txt文件
- `-s <密钥>` - 签名密钥（默认：secret）
- `-a <算法>` - 签名算法（默认：HS256）

**支持算法：** HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512

**示例：**
```bash
# 基本用法（推荐：所有平台通用）
jwt_cli sign -p '{"sub":"user123","name":"Admin"}'

# 从文件读取（Windows CMD 用户）
jwt_cli sign -p payload.json

# 自定义密钥和算法
jwt_cli sign -s mykey -a HS512 -p '{"user":"admin"}'

# 设置过期时间（Unix时间戳）
jwt_cli sign -p '{"sub":"user123","exp":9999999999}'
```

### crack - 爆破JWT密钥

使用字典攻击破解JWT签名密钥。

```bash
jwt_cli crack [jwt_token] [选项]
```

**选项：**
- `-w <文件>` - 密码字典文件（可选，不指定则使用内置84个常见弱密码）
- `-t <线程数>` - 并发线程数（默认：1）

**注意：** 仅支持HMAC系列算法（HS256/HS384/HS512）

**示例：**
```bash
# 使用内置字典
jwt_cli crack <token>

# 使用外部字典
jwt_cli crack <token> -w wordlist.txt

# 多线程爆破
jwt_cli crack <token> -w rockyou.txt -t 16
```

## 内置密码列表

工具内置84个常见弱密码，包括：

```
secret, password, 123456, admin, test, 12345678, qwerty,
letmein, password123, admin123, root, mysecret, secretkey,
jwtkey, jwtsecret, api_secret, authkey, authsecret, token_secret...
```

## 使用场景

### 渗透测试

```bash
# 1. 分析JWT内容
jwt_cli decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# 2. 使用大字典爆破
jwt_cli decode <token> -w /usr/share/wordlists/rockyou.txt -t 16

# 3. 伪造令牌
jwt_cli sign -s cracked_key -p '{"sub":"admin","role":"admin"}'
```

### 开发测试

```bash
# 生成测试令牌
jwt_cli sign -s dev_secret -p '{"user":"test","exp":9999999999}'
```

## 示例输出

```bash
$ jwt_cli decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

=== JWT 解密结果 ===

Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

Payload:
{
  "sub": "user123",
  "name": "Admin",
  "exp": 1767193387
}

=== 签名验证 ===
使用内置字典爆破密钥 (84个密码, 线程数: 4)
✓ 找到密钥: mysecret (耗时: 468µs, 尝试: 73)
```

## 项目结构

```
jwt_cli/
├── main.go       # 主程序
├── jwt.go        # JWT核心功能
├── go.mod        # Go模块
├── README.md     # 文档
└── jwt_cli       # 编译后的可执行文件
```

## 免责声明

本工具仅供学习和授权的安全测试使用。用户需对使用本工具的行为负责。
