Auther - TOTP 认证管理器

https://img.shields.io/badge/Rust-1.60%2B-orange?logo=rust https://img.shields.io/badge/License-MIT-yellow.svg https://img.shields.io/badge/Release-1.0.0-blue

一个使用 Rust 编写的 TOTP (基于时间的一次性密码) 认证管理器，提供命令行界面和文本用户界面两种操作方式，帮助您安全地管理双重认证令牌。

功能特点

· 🔐 安全的 TOTP 密钥存储与管理
· 🖥️ 直观的文本用户界面 (TUI) 和命令行界面 (CLI)
· 📱 支持从 QR 码图像导入密钥
· 🖨️ 支持为现有密钥生成 QR 码
· 📋 一键复制验证码到剪贴板
· ⏰ 实时显示验证码剩余有效时间
· 🔧 跨平台支持 (Windows, macOS, Linux)

安装

从预编译版本安装

1. 访问 Release 页面
2. 下载适用于您操作系统的最新版本
3. 解压文件并将可执行文件添加到系统 PATH 中

从源码编译

需要先安装 Rust 工具链

```bash
# 克隆项目
git clone https://github.com/yourusername/auther.git
cd auther

# 编译发布版本
cargo build --release

# 编译后的可执行文件位于 target/release/auther
```

使用方法

TUI 模式 (文本用户界面)

直接运行程序即可进入 TUI 模式：

```bash
auther
```

或明确指定 TUI 模式：

```bash
auther tui
```

TUI 模式快捷键：

· ↑/k, ↓/j - 上下选择账户
· a - 添加新密钥
· r - 删除当前密钥
· q - 从 QR 码图像添加密钥
· g - 为当前密钥生成 QR 码
· c - 复制当前验证码到剪贴板
· Esc - 退出

CLI 模式 (命令行界面)

```bash
# 添加新密钥
auther add <名称>

# 从 QR 码图像添加密钥
auther add-qr <二维码路径>

# 为现有密钥生成 QR 码
auther generate-qr <名称> <发行商> <输出路径>

# 获取当前 TOTP 码
auther get <名称>

# 获取并复制 TOTP 码到剪贴板
auther get <名称> --copy

# 列出所有存储的密钥
auther list

# 删除密钥
auther remove <名称>

# 显示当前时间窗口信息
auther time-window

# 生成当前时间窗口及其前后窗口的 TOTP 码
auther generate-codes <名称>
```

配置

程序配置文件自动存储在可执行文件同目录下的 config.json 文件中。所有密钥均以 Base32 编码格式安全存储。

依赖项

· ratatui - 文本用户界面库
· crossterm - 跨平台终端操作
· qrcode - QR 码生成
· quircs - QR 码解码
· chrono - 日期和时间处理
· serde - 序列化/反序列化
· zeroize - 安全内存清零

安全性

· 所有密钥在内存中使用 Zeroizing 包装器保护，防止内存泄漏
· 配置文件仅存储 Base32 编码的密钥
· 程序不依赖网络连接，所有操作在本地完成

贡献

欢迎提交 Issue 和 Pull Request！对于重大更改，请先开 Issue 讨论您想要更改的内容。

许可证

本项目采用 MIT 许可证 - 查看 LICENSE 文件了解详情。

致谢

感谢所有为本项目提供灵感和代码的开源项目。

---

注意：请妥善保管您的密钥备份，丢失密钥可能导致无法访问相关账户的双重认证。
