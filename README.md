# Authtui - TOTP 认证管理器

![Rust](https://img.shields.io/badge/Rust-1.90%2B-orange?logo=rust)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Release](https://img.shields.io/badge/Release-1.0.1-blue)

Authtui 是一个使用 Rust 编写的 TOTP（基于时间的一次性密码）认证管理器，提供命令行（CLI）和文本用户界面（TUI）两种操作方式，帮助您安全且高效地管理您的双重认证密钥。

---

## 功能特点

- 🔐 **安全存储**：TOTP 密钥安全加密存储与管理
- 🖥️ **界面友好**：支持 TUI 和 CLI 两种操作方式
- 📱 **密钥导入**：可从 QR 码图像导入密钥
- 🖨️ **二维码生成**：为现有密钥生成 QR 码
- 📋 **便捷复制**：一键复制验证码到剪贴板
- ⏰ **实时显示**：展示验证码剩余有效时间
- 🔧 **跨平台**：兼容 Windows、macOS、Linux

---

## 安装方法

### AUR（Arch 用户仓库）

如果您使用 Arch Linux 或其衍生发行版，可以通过 AUR 包 [authtui-git](https://aur.archlinux.org/packages/authtui-git) 安装：

```bash
yay -S authtui-git
# 或使用其他 AUR 助手
paru -S authtui-git
```

### 预编译版本

1. 前往 [Release 页面](https://github.com/d116u/authtui/releases)
2. 下载适合您操作系统的最新版本
3. 解压文件，将可执行文件添加到系统 `PATH`

### 源码编译

确保已安装 [Rust 工具链](https://rust-lang.org/tools/install)

```bash
# 克隆项目
git clone https://github.com/yourusername/auther.git
cd auther

# 编译发布版本
cargo build --release

# 可执行文件位于 target/release/auther
```

---

## 使用方法

### TUI 模式（文本用户界面）

直接运行即可进入 TUI 模式：

```bash
auther
```

或显式指定：

```bash
auther tui
```

#### TUI 快捷键

| 快捷键       | 功能描述                 |
|--------------|--------------------------|
| ↑/k, ↓/j     | 上下选择账户             |
| a            | 添加新密钥               |
| r            | 删除当前密钥             |
| q            | 从 QR 码图像添加密钥     |
| g            | 为当前密钥生成 QR 码     |
| c            | 复制当前验证码到剪贴板   |
| Esc          | 退出                     |

---

### CLI 模式（命令行界面）

```bash
auther add <名称>                       # 添加新密钥
auther add-qr <二维码路径>              # 从 QR 码图像添加密钥
auther generate-qr <名称> <发行商> <输出路径> # 为密钥生成 QR 码
auther get <名称>                       # 获取当前 TOTP 码
auther get <名称> --copy                # 获取并复制 TOTP 码到剪贴板
auther list                             # 列出所有密钥
auther remove <名称>                    # 删除密钥
auther time-window                      # 显示当前时间窗口信息
auther generate-codes <名称>            # 生成当前及前后窗口的 TOTP 码
```

---

## 配置说明

- 程序会在可执行文件同目录下自动生成 `config.json` 配置文件
- 所有密钥均以 Base32 编码格式安全存储

---

## 依赖项

- [ratatui](https://crates.io/crates/ratatui) - 文本用户界面库
- [crossterm](https://crates.io/crates/crossterm) - 跨平台终端操作
- [qrcode](https://crates.io/crates/qrcode) - QR 码生成
- [quircs](https://crates.io/crates/quircs) - QR 码解码
- [chrono](https://crates.io/crates/chrono) - 日期时间处理
- [serde](https://crates.io/crates/serde) - 序列化/反序列化
- [zeroize](https://crates.io/crates/zeroize) - 安全内存清零

---

## 安全性

- 所有密钥在内存中均通过 Zeroizing 包装器保护，防止泄露
- 配置文件仅存储 Base32 编码的密钥
- 程序完全本地运行，无需网络连接

---

## 贡献方式

欢迎提交 Issue 和 Pull Request！重大修改请先开 Issue 讨论您的想法。

---

## 许可证

本项目采用 [MIT 许可证](LICENSE)。

---

## 致谢

感谢所有为本项目提供灵感和帮助的开源项目。

---

> ⚠️ **提示**：请妥善备份您的密钥，丢失密钥可能导致无法访问相关账户的双重认证。
