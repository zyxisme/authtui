// 启用必要的编译器特性
// #![feature(some_feature)]

// 导入标准库模块
use std::{
    collections::HashMap,    // 哈希映射，用于存储键值对
    env,                    // 环境变量操作
    error::Error,           // 错误处理 trait
    fs::{File, OpenOptions}, // 文件系统操作
    io::{BufReader, BufWriter}, // 缓冲读写器，提高I/O性能
    path::Path,             // 路径操作
    process,                // 进程控制
    str::FromStr,           // 字符串解析
};

// 导入第三方库
use chrono::{DateTime, Local, TimeDelta}; // 日期和时间处理
use data_encoding::BASE32;  // Base32编码/解码
use image::GenericImageView; // 图像处理，用于QR码解码
use qrcode::QrCode;         // QR码生成
use rand::{rngs::OsRng, RngCore};        // 随机数生成
use rpassword::read_password;             // 安全读取密码（不显示在终端）
use serde::{Deserialize, Serialize};      // 序列化和反序列化
use url::Url;                // URL解析
use zeroize::Zeroizing;                   // 安全清零内存中的敏感数据

/// 表示整个应用程序配置和状态的结构体
#[derive(Debug, Serialize, Deserialize)]
struct App {
    // 使用 Zeroizing 包装敏感数据，确保在内存中安全并能在丢弃时清零
    keys: HashMap<String, Zeroizing<String>>,
}

/// 表示时间窗口的结构体，用于TOTP计算
#[derive(Debug)]
struct TimeWindow {
    start: DateTime<Local>,  // 时间窗口开始时间
    end: DateTime<Local>,    // 时间窗口结束时间
}

/// 从otpauth URL解析出的TOTP参数
#[derive(Debug)]
struct OtpAuthParams {
    secret: String,          // Base32编码的密钥
    issuer: Option<String>,  // 发行商/服务提供商
    account: Option<String>, // 账户名
    algorithm: Option<String>, // 哈希算法（默认SHA1）
    digits: Option<u32>,     // 验证码位数（默认6）
    period: Option<u64>,     // 时间步长（默认30秒）
}

impl App {
    /// 从文件加载应用程序状态
    fn load() -> Result<Self, Box<dyn Error>> {
        // 获取配置文件路径
        let path = App::get_path()?;
        
        // 如果配置文件不存在，则创建一个新的应用程序实例
        if !path.exists() {
            return Ok(App {
                keys: HashMap::new(),
            });
        }

        // 打开文件并使用BufReader提高读取性能
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        
        // 从JSON格式反序列化数据
        let app: App = serde_json::from_reader(reader)?;
        
        Ok(app)
    }

    /// 保存应用程序状态到文件
    fn save(&self) -> Result<(), Box<dyn Error>> {
        // 获取配置文件路径
        let path = App::get_path()?;
        
        // 创建或打开文件，使用BufWriter提高写入性能
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        let writer = BufWriter::new(file);
        
        // 将数据序列化为JSON格式并写入文件
        serde_json::to_writer_pretty(writer, self)?;
        
        Ok(())
    }

    /// 获取配置文件路径
    fn get_path() -> Result<std::path::PathBuf, Box<dyn Error>> {
        // 获取当前可执行文件所在目录
        let mut path = env::current_exe()?;
        path.pop(); // 移除可执行文件名，只保留目录路径
        
        // 拼接配置文件名
        path.push("config.json");
        
        Ok(path)
    }

    /// 添加新的密钥到应用程序
    fn add_key(&mut self, name: String, key: Zeroizing<String>) {
        self.keys.insert(name, key);
    }

    /// 根据名称获取密钥
    fn get_key(&self, name: &str) -> Option<&Zeroizing<String>> {
        self.keys.get(name)
    }

    /// 列出所有存储的密钥名称
    fn list_keys(&self) -> Vec<&String> {
        self.keys.keys().collect()
    }

    /// 根据名称删除密钥
    fn remove_key(&mut self, name: &str) -> Option<Zeroizing<String>> {
        self.keys.remove(name)
    }
}

/// 生成随机密钥的函数
fn generate_key() -> Zeroizing<String> {
    // 创建密码学安全的随机数生成器
    let mut rng = OsRng;
    
    // 创建20字节的缓冲区（160位，适合TOTP）
    let mut buffer = [0u8; 20];
    
    // 用随机数据填充缓冲区
    rng.fill_bytes(&mut buffer);
    
    // 将字节编码为Base32字符串（TOTP标准使用的编码）
    let key = BASE32.encode(&buffer);
    
    // 用Zeroizing包装返回，确保安全存储
    Zeroizing::new(key)
}

/// 计算TOTP码的函数
fn calculate_totp(key: &str, time: DateTime<Local>) -> Result<String, Box<dyn Error>> {
    // 将Base32编码的密钥解码为字节
    let decoded_key = BASE32.decode(key.as_bytes())
        .map_err(|_| "Invalid base32 key")?;
    
    // 计算时间步数（通常每30秒一步）
    let time_step = 30;
    let timestamp = time.timestamp() as u64;
    let counter = timestamp / time_step;
    
    // 使用HMAC-SHA1算法计算哈希
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    
    type HmacSha1 = Hmac<Sha1>;
    
    let mut hmac = HmacSha1::new_from_slice(&decoded_key)?;
    hmac.update(&counter.to_be_bytes());
    let result = hmac.finalize();
    let code_bytes = result.into_bytes();
    
    // 动态截取计算OTP
    let offset = (code_bytes[19] & 0x0f) as usize;
    let code = ((u32::from(code_bytes[offset]) & 0x7f) << 24
        | (u32::from(code_bytes[offset + 1]) & 0xff) << 16
        | (u32::from(code_bytes[offset + 2]) & 0xff) << 8
        | (u32::from(code_bytes[offset + 3]) & 0xff))
        % 1_000_000;
    
    // 格式化为6位数字，不足补零
    Ok(format!("{:06}", code))
}

/// 获取当前时间窗口的函数
fn get_time_window(window: u64) -> TimeWindow {
    let now = Local::now();
    let time_step = 30;
    let timestamp = now.timestamp() as u64;
    let counter = timestamp / time_step;
    
    let window_start = counter * time_step;
    let window_end = window_start + time_step - 1;
    
    TimeWindow {
        start: DateTime::from_timestamp(window_start as i64, 0).unwrap().into(),
        end: DateTime::from_timestamp(window_end as i64, 0).unwrap().into(),
    }
}

/// 从QR码图像中解码TOTP URI
fn decode_qr_code(image_path: &str) -> Result<String, Box<dyn Error>> {
    // 打开图像文件
    let img = image::open(image_path)?;
    
    // 准备QR码解码器
    let mut decoder = quircs::Quirc::default();
    
    // 将图像转换为灰度图
    let gray_img = img.to_luma8();
    
    // 获取图像尺寸
    let (width, height) = gray_img.dimensions();
    
    // 解码QR码
    let codes = decoder.identify(width as usize, height as usize, &gray_img);
    
    for code in codes {
        let code = code?;
        let decoded = code.decode()?;
        return Ok(String::from_utf8(decoded.payload)?);
    }
    
    Err("No QR code found in the image".into())
}

/// 解析otpauth URL并提取TOTP参数
fn parse_otpauth_uri(uri: &str) -> Result<OtpAuthParams, Box<dyn Error>> {
    let url = Url::parse(uri)?;
    
    // 确保是otpauth协议
    if url.scheme() != "otpauth" {
        return Err("Not an otpauth URI".into());
    }
    
    // 确保是TOTP类型
    if url.host_str() != Some("totp") {
        return Err("Only TOTP is supported".into());
    }
    
    // 提取路径中的标签（通常格式：发行商:账户名）
    let label = url.path().trim_start_matches('/');
    let (issuer, account) = if let Some(colon_pos) = label.find(':') {
        (
            Some(label[..colon_pos].to_string()),
            Some(label[colon_pos + 1..].to_string())
        )
    } else {
        (None, Some(label.to_string()))
    };
    
    // 提取查询参数
    let query_pairs = url.query_pairs();
    let mut params = OtpAuthParams {
        secret: String::new(),
        issuer,
        account,
        algorithm: None,
        digits: None,
        period: None,
    };
    
    for (key, value) in query_pairs {
        match key.as_ref() {
            "secret" => params.secret = value.into_owned(),
            "issuer" => params.issuer = Some(value.into_owned()),
            "algorithm" => params.algorithm = Some(value.into_owned()),
            "digits" => params.digits = Some(value.parse::<u32>()?),
            "period" => params.period = Some(value.parse::<u64>()?),
            _ => {} // 忽略未知参数
        }
    }
    
    // 检查必需参数
    if params.secret.is_empty() {
        return Err("Missing secret parameter".into());
    }
    
    Ok(params)
}

/// 生成TOTP配置的QR码并保存为PNG图像
fn generate_qr_code(
    secret: &str, 
    account_name: &str, 
    issuer: &str, 
    output_path: &str
) -> Result<(), Box<dyn Error>> {
    // 构建otpauth URI
    let otpauth_uri = format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        issuer, account_name, secret, issuer
    );
    
    // 生成QR码
    let code = QrCode::new(otpauth_uri.as_bytes())?;
    
    // 将QR码渲染为图像
    let image = code.render::<image::Luma<u8>>().build();
    
    // 保存图像
    image.save(output_path)?;
    
    println!("QR code saved to: {}", output_path);
    Ok(())
}

/// 主函数
fn main() -> Result<(), Box<dyn Error>> {
    // 加载应用程序状态
    let mut app = App::load()?;
    
    // 获取命令行参数
    let args: Vec<String> = env::args().collect();
    
    // 根据参数执行不同操作
    if args.len() < 2 {
        // 如果没有提供子命令，显示用法信息
        print_usage();
        process::exit(1);
    }
    
    match args[1].as_str() {
        "add" => {
            // 添加新密钥
            if args.len() < 3 {
                eprintln!("需要提供名称参数");
                process::exit(1);
            }
            
            let name = &args[2];
            let key = generate_key();
            
            app.add_key(name.clone(), key);
            app.save()?;
            
            println!("已为 '{}' 添加新密钥", name);
        }
        "add-qr" => {
            // 从QR码图像添加密钥
            if args.len() < 3 {
                eprintln!("需要提供QR码图像路径");
                process::exit(1);
            }
            
            let image_path = &args[2];
            
            // 解码QR码
            let otpauth_uri = decode_qr_code(image_path)?;
            println!("解码的URI: {}", otpauth_uri);
            
            // 解析URI
            let params = parse_otpauth_uri(&otpauth_uri)?;
            
            // 确定密钥名称（优先使用发行商+账户名组合）
            let name = if let (Some(issuer), Some(account)) = (&params.issuer, &params.account) {
                format!("{}:{}", issuer, account)
            } else if let Some(account) = &params.account {
                account.clone()
            } else {
                return Err("无法从QR码确定账户名称".into());
            };
            
            // 添加密钥
            app.add_key(name.clone(), Zeroizing::new(params.secret));
            app.save()?;
            
            println!("已从QR码添加密钥: {}", name);
        }
        "generate-qr" => {
            // 为现有密钥生成QR码
            if args.len() < 4 {
                eprintln!("需要提供密钥名称、发行商和输出路径");
                process::exit(1);
            }
            
            let name = &args[2];
            let issuer = &args[3];
            let output_path = &args[4];
            
            if let Some(key) = app.get_key(name) {
                generate_qr_code(&key, name, issuer, output_path)?;
            } else {
                eprintln!("未找到 '{}' 的密钥", name);
                process::exit(1);
            }
        }
        "get" => {
            // 获取TOTP码
            if args.len() < 3 {
                eprintln!("需要提供名称参数");
                process::exit(1);
            }
            
            let name = &args[2];
            
            if let Some(key) = app.get_key(name) {
                let code = calculate_totp(&key, Local::now())?;
                println!("{} 的验证码: {}", name, code);
            } else {
                eprintln!("未找到 '{}' 的密钥  woo", name);
                process::exit(1);
            }
        }
        "list" => {
            // 列出所有密钥名称
            let keys = app.list_keys();
            
            if keys.is_empty() {
                println!("未存储任何密钥");
            } else {
                println!("存储的密钥:");
                for key in keys {
                    println!("  {}", key);
                }
            }
        }
        "remove" => {
            // 删除密钥
            if args.len() < 3 {
                eprintln!("需要提供名称参数");
                process::exit(1);
            }
            
            let name = &args[2];
            
            if app.remove_key(name).is_some() {
                app.save()?;
                println!("已删除 '{}' 的密钥", name);
            } else {
                eprintln!("未找到 '{}' 的密钥", name);
                process::exit(1);
            }
        }
        "time-window" => {
            // 显示当前时间窗口信息
            let window = get_time_window(1);
            println!("当前时间窗口: {} 到 {}", window.start, window.end);
            
            let now = Local::now();
            let remaining = (window.end - now).num_seconds();
            println!("剩余时间: {} 秒", remaining);
        }
        "generate-codes" => {
            // 生成当前时间窗口及其前后窗口的TOTP码
            if args.len() < 3 {
                eprintln!("需要提供名称参数");
                process::exit(1);
            }
            
            let name = &args[2];
            
            if let Some(key) = app.get_key(name) {
                let window: u64 = 1; // 显示前后1个窗口
                
                // 修复错误：先转换为有符号整数，再取负
                for i in (-(window as i64))..=(window as i64) {
                    let time = Local::now() + TimeDelta::seconds(i * 30);
                    let code = calculate_totp(&key, time)?;
                    
                    if i == 0 {
                        println!("[*] {}: {}", time.format("%H:%M:%S"), code);
                    } else {
                        println!("[ ] {}: {}", time.format("%H:%M:%S"), code);
                    }
                }
            } else {
                eprintln!("未找到 '{}' 的密钥", name);
                process::exit(1);
            }
        }
        _ => {
            // 未知命令
            eprintln!("未知命令: {}", args[1]);
            print_usage();
            process::exit(1);
        }
    }
    
    Ok(())
}

/// 打印使用说明的函数
fn print_usage() {
    println!("用法: auther <命令> [参数]");
    println!();
    println!("命令:");
    println!("  add <名称>             添加新密钥");
    println!("  add-qr <二维码路径>     从QR码图像添加密钥");
    println!("  generate-qr <名称> <发行商> <输出路径> 为现有密钥生成QR码");
    println!("  get <名称>             获取当前TOTP码");
    println!("  list                   列出所有存储的密钥");
    println!("  remove <名称>          删除密钥");
    println!("  time-window            显示当前时间窗口信息");
    println!("  generate-codes <名称>  生成当前时间窗口及其前后窗口的TOTP码");
}
