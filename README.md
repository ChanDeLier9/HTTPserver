# 轻量级 HTTP 服务器

一个用 C 语言实现的轻量级、多线程 HTTP 服务器。本项目展示了核心 Web 服务器概念，包括静态文件服务、配置管理、日志记录以及多种认证机制（Basic 认证、Session、JWT）。

## ✨ 功能特性

- **静态文件服务**：支持 HTML、CSS、JS、图片等文件的访问。
- **可配置**：通过 `config.json` 管理服务器设置。
- **搜索引擎**：基于文件的搜索功能（`/search`），查询 `2011.txt` 数据。
- **认证机制**：
  - **Basic 认证**：保护 `/secured` 端点。
  - **Session 认证**：基于 Cookie 的会话管理（`/session_login`, `/session`）。
  - **JWT 认证**：基于 Token 的认证（`/jwt_login`, `/jwt`）。
- **日志记录**：提供详细的系统日志和访问日志，支持配置日志等级。
- **安全性**：基础的路径遍历防护。

## 🛠️ 依赖项

- **GCC**：C 语言编译器。
- **OpenSSL**：用于 JWT 签名/验证（`libcrypto`）。
- **cJSON**：JSON 解析（项目中已包含：`cJSON.c`, `cJSON.h`）。
- **POSIX 环境**：Linux、macOS 或 Windows (通过 WSL/MinGW/Cygwin)。

## 🚀 编译与运行

### 1. 编译
本项目需要链接 `pthread`（用于线程支持）和 `crypto`（用于 OpenSSL）。

```bash
gcc http_server.c cJSON.c -o http_server -lpthread -lcrypto
```

### 2. 配置
确保 `config.json` 位于可执行文件的同一目录下。默认配置：

```json
{
  "server": {
    "address": "127.0.0.1",
    "port": 8080
  },
  "auth": {
    "username": "admin",
    "password": "123456"
  },
  ...
}
```

### 3. 启动服务器
```bash
./http_server
```
*注意：`log` 目录将自动创建。*

## 🔌 API 接口

| 路径 | 方法 | 描述 | 鉴权要求 |
|------|--------|-------------|---------------|
| `/` | GET | 首页（静态页面） | 无 |
| `/search` | GET/POST | 搜索接口。POST 参数：`class` & `keyword`。 | 无 |
| `/secured` | GET | Basic 认证演示区域。 | **Basic** |
| `/session_login` | POST | 登录获取 Session Cookie。参数：`username`, `password` | 无 |
| `/session` | GET | 验证 Session Cookie。 | **Session** |
| `/jwt_login` | POST | 登录获取 JWT Token。参数：`username`, `password` | 无 |
| `/jwt` | GET | 验证 Bearer Token。Header：`Authorization: Bearer <token>` | **JWT** |

## 📂 项目结构

- `http_server.c`: 服务器主源代码。
- `cJSON.c/h`: JSON 解析库。
- `config.json`: 服务器配置文件。
- `2011.txt`: 搜索功能的数据源。
- `index.html`, `search.html`: 前端页面。
- `log/`: 存放 `access.log` 和 `system.log`。

## 📝 许可说明
本项目仅供学习和实习使用。
