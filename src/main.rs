// 导入标准库模块
use std::{
    collections::HashMap,
    env,
    error::Error,
    fs::{File, OpenOptions},
    io::{self, BufReader, BufWriter},
    path::Path,
    process,
    process::Command,
    str::FromStr,
    time::{Duration, Instant},
};

// 导入第三方库
use chrono::{DateTime, Local, TimeDelta};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use data_encoding::BASE32;
use image::GenericImageView;
use qrcode::QrCode;
use rand::{rngs::OsRng, RngCore};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

/// 表示整个应用程序配置和状态的结构体
#[derive(Debug, Serialize, Deserialize)]
struct App {
    keys: HashMap<String, Zeroizing<String>>,
}

/// 表示时间窗口的结构体，用于TOTP计算
#[derive(Debug)]
struct TimeWindow {
    start: DateTime<Local>,
    end: DateTime<Local>,
}

/// 从otpauth URL解析出的TOTP参数
#[derive(Debug)]
struct OtpAuthParams {
    secret: String,
    issuer: Option<String>,
    account: Option<String>,
    algorithm: Option<String>,
    digits: Option<u32>,
    period: Option<u64>,
}

/// TUI应用程序状态
struct TuiApp {
    app: App,
    list_state: ListState,
    current_code: Option<String>,
    current_account: Option<String>,
    remaining_time: u64,
    should_quit: bool,
    message: Option<String>,
    message_timer: Option<Instant>,
    current_screen: Screen,
    input_mode: InputMode,
    input_buffer: String,
    last_update: Instant,
}

/// TUI屏幕状态
#[derive(PartialEq)]
enum Screen {
    Main,
    AddKey,
    AddKeyQr,
    GenerateQr,
    RemoveKey,
}

/// 输入模式
enum InputMode {
    Normal,
    Editing,
}

impl TuiApp {
    fn new(app: App) -> Self {
        let mut list_state = ListState::default();
        if !app.keys.is_empty() {
            list_state.select(Some(0));
        }

        let mut app_instance = Self {
            app,
            list_state,
            current_code: None,
            current_account: None,
            remaining_time: 0,
            should_quit: false,
            message: None,
            message_timer: None, // 修复：使用冒号而不是等号
            current_screen: Screen::Main,
            input_mode: InputMode::Normal,
            input_buffer: String::new(),
            last_update: Instant::now(),
        };
        
        // 初始更新验证码
        app_instance.update_current_code();
        app_instance
    }

    fn next(&mut self) {
        let i = match self.list_state.selected() {
            Some(i) => {
                if i >= self.app.keys.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
        self.update_current_code();
    }

    fn previous(&mut self) {
        let i = match self.list_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.app.keys.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
        self.update_current_code();
    }

    fn update_current_code(&mut self) {
        if let Some(selected) = self.list_state.selected() {
            if let Some((name, _)) = self.app.keys.iter().nth(selected) {
                // 只有当选择的账户发生变化时才更新验证码
                if self.current_account.as_ref() != Some(name) {
                    self.current_account = Some(name.clone());
                    if let Some(key) = self.app.get_key(name) {
                        match calculate_totp(&key, Local::now()) {
                            Ok(code) => {
                                self.current_code = Some(code);
                                self.update_remaining_time();
                                self.last_update = Instant::now();
                            }
                            Err(e) => {
                                self.show_message(format!("错误: {}", e), Duration::from_secs(3));
                                self.current_code = None;
                            }
                        }
                    }
                }
            }
        } else {
            self.current_code = None;
            self.current_account = None;
        }
    }

    fn update_remaining_time(&mut self) {
        let now = Local::now();
        let time_step = 30;
        let timestamp = now.timestamp() as u64;
        let counter = timestamp / time_step;
        let window_end = (counter + 1) * time_step;
        self.remaining_time = window_end - timestamp;
    }

    fn show_message(&mut self, message: String, duration: Duration) {
        self.message = Some(message);
        self.message_timer = Some(Instant::now() + duration);
    }

    fn check_message_timer(&mut self) {
        if let Some(timer) = self.message_timer {
            if Instant::now() >= timer {
                self.message = None;
                self.message_timer = None;
            }
        }
    }

    // 添加方法检查是否需要更新验证码
    fn check_and_update_code(&mut self) {
        // 每秒钟检查一次是否需要更新验证码
        if self.last_update.elapsed() >= Duration::from_secs(1) {
            self.update_remaining_time();
            
            // 如果剩余时间重置（从1跳到30），说明时间步长已变化，需要更新验证码
            if self.remaining_time == 30 {
                if let Some(account) = &self.current_account {
                    if let Some(key) = self.app.get_key(account) {
                        match calculate_totp(&key, Local::now()) {
                            Ok(code) => {
                                self.current_code = Some(code);
                                self.last_update = Instant::now();
                            }
                            Err(e) => {
                                self.show_message(format!("错误: {}", e), Duration::from_secs(3));
                                self.current_code = None;
                            }
                        }
                    }
                }
            }
        }
    }

    // 使用系统命令复制到剪贴板
    fn copy_to_clipboard(&mut self) {
        if let Some(code) = &self.current_code {
            // 尝试使用系统命令复制到剪贴板
            if let Err(e) = copy_to_clipboard_system(&code) {
                self.show_message(format!("复制失败: {}", e), Duration::from_secs(3));
            } else {
                self.show_message("验证码已复制到剪贴板".to_string(), Duration::from_secs(2));
            }
        } else {
            self.show_message("没有可复制的验证码".to_string(), Duration::from_secs(2));
        }
    }

    fn add_key(&mut self, name: String, key: Zeroizing<String>) {
        self.app.add_key(name.clone(), key);
        if let Err(e) = self.app.save() {
            self.show_message(format!("保存失败: {}", e), Duration::from_secs(3));
        } else {
            self.show_message(format!("已添加密钥: {}", name), Duration::from_secs(2));
            // 更新列表选择状态
            if self.app.keys.len() == 1 {
                self.list_state.select(Some(0));
            }
            self.update_current_code();
        }
    }

    fn remove_selected_key(&mut self) {
        if let Some(selected) = self.list_state.selected() {
            if let Some((name, _)) = self.app.keys.iter().nth(selected) {
                let name_clone = name.clone();
                if self.app.remove_key(&name_clone).is_some() {
                    if let Err(e) = self.app.save() {
                        self.show_message(format!("保存失败: {}", e), Duration::from_secs(3));
                    } else {
                        self.show_message(format!("已删除密钥: {}", name_clone), Duration::from_secs(2));
                        
                        // 调整选择状态
                        if self.app.keys.is_empty() {
                            self.list_state.select(None);
                            self.current_code = None;
                            self.current_account = None;
                        } else if selected >= self.app.keys.len() {
                            self.list_state.select(Some(self.app.keys.len() - 1));
                        }
                        self.update_current_code();
                    }
                }
            }
        }
    }
}

impl App {
    fn load() -> Result<Self, Box<dyn Error>> {
        let path = App::get_path()?;
        
        if !path.exists() {
            return Ok(App {
                keys: HashMap::new(),
            });
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let app: App = serde_json::from_reader(reader)?;
        
        Ok(app)
    }

    fn save(&self) -> Result<(), Box<dyn Error>> {
        let path = App::get_path()?;
        
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        let writer = BufWriter::new(file);
        
        serde_json::to_writer_pretty(writer, self)?;
        
        Ok(())
    }

    fn get_path() -> Result<std::path::PathBuf, Box<dyn Error>> {
        let mut path = env::current_exe()?;
        path.pop();
        path.push("config.json");
        Ok(path)
    }

    fn add_key(&mut self, name: String, key: Zeroizing<String>) {
        self.keys.insert(name, key);
    }

    fn get_key(&self, name: &str) -> Option<&Zeroizing<String>> {
        self.keys.get(name)
    }

    fn list_keys(&self) -> Vec<&String> {
        self.keys.keys().collect()
    }

    fn remove_key(&mut self, name: &str) -> Option<Zeroizing<String>> {
        self.keys.remove(name)
    }
}

fn generate_key() -> Zeroizing<String> {
    let mut rng = OsRng;
    let mut buffer = [0u8; 20];
    rng.fill_bytes(&mut buffer);
    let key = BASE32.encode(&buffer);
    Zeroizing::new(key)
}

fn calculate_totp(key: &str, time: DateTime<Local>) -> Result<String, Box<dyn Error>> {
    let decoded_key = BASE32.decode(key.as_bytes())
        .map_err(|_| "Invalid base32 key")?;
    
    let time_step = 30;
    let timestamp = time.timestamp() as u64;
    let counter = timestamp / time_step;
    
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    
    type HmacSha1 = Hmac<Sha1>;
    
    let mut hmac = HmacSha1::new_from_slice(&decoded_key)?;
    hmac.update(&counter.to_be_bytes());
    let result = hmac.finalize();
    let code_bytes = result.into_bytes();
    
    let offset = (code_bytes[19] & 0x0f) as usize;
    let code = ((u32::from(code_bytes[offset]) & 0x7f) << 24
        | (u32::from(code_bytes[offset + 1]) & 0xff) << 16
        | (u32::from(code_bytes[offset + 2]) & 0xff) << 8
        | (u32::from(code_bytes[offset + 3]) & 0xff))
        % 1_000_000;
    
    Ok(format!("{:06}", code))
}

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

fn decode_qr_code(image_path: &str) -> Result<String, Box<dyn Error>> {
    let img = image::open(image_path)?;
    let mut decoder = quircs::Quirc::default();
    let gray_img = img.to_luma8();
    let (width, height) = gray_img.dimensions();
    
    let codes = decoder.identify(width as usize, height as usize, &gray_img);
    
    for code in codes {
        let code = code?;
        let decoded = code.decode()?;
        return Ok(String::from_utf8(decoded.payload)?);
    }
    
    Err("No QR code found in the image".into())
}

fn parse_otpauth_uri(uri: &str) -> Result<OtpAuthParams, Box<dyn Error>> {
    let url = Url::parse(uri)?;
    
    if url.scheme() != "otpauth" {
        return Err("Not an otpauth URI".into());
    }
    
    if url.host_str() != Some("totp") {
        return Err("Only TOTP is supported".into());
    }
    
    let label = url.path().trim_start_matches('/');
    let (issuer, account) = if let Some(colon_pos) = label.find(':') {
        (
            Some(label[..colon_pos].to_string()),
            Some(label[colon_pos + 1..].to_string())
        )
    } else {
        (None, Some(label.to_string()))
    };
    
    let query_pairs = url.query_pairs();
    let mut params = OtpAuthParams {
        secret: String::new(),
        issuer,
        account,
        algorithm: None,
        digits: None,
        period: None,
    };
    
    for (key, value) in query_pairs { // 修复：添加in关键字
        match key.as_ref() {
            "secret" => params.secret = value.into_owned(),
            "issuer" => params.issuer = Some(value.into_owned()),
            "algorithm" => params.algorithm = Some(value.into_owned()),
            "digits" => params.digits = Some(value.parse::<u32>()?),
            "period" => params.period = Some(value.parse::<u64>()?),
            _ => {}
        }
    }
    
    if params.secret.is_empty() {
        return Err("Missing secret parameter".into());
    }
    
    Ok(params)
}

fn generate_qr_code(
    secret: &str, 
    account_name: &str, 
    issuer: &str, 
    output_path: &str
) -> Result<(), Box<dyn Error>> {
    let otpauth_uri = format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        issuer, account_name, secret, issuer
    );
    
    let code = QrCode::new(otpauth_uri.as_bytes())?;
    let image = code.render::<image::Luma<u8>>().build();
    image.save(output_path)?;
    
    println!("QR code saved to: {}", output_path);
    Ok(())
}

// 使用系统命令复制到剪贴板
fn copy_to_clipboard_system(text: &str) -> Result<(), Box<dyn Error>> {
    // 根据操作系统选择合适的命令
    if cfg!(target_os = "macos") {
        // macOS
        let mut cmd = Command::new("pbcopy");
        cmd.stdin(std::process::Stdio::piped());
        let mut child = cmd.spawn()?;
        {
            let stdin = child.stdin.as_mut().ok_or("Failed to open stdin")?;
            use std::io::Write;
            stdin.write_all(text.as_bytes())?;
        }
        child.wait()?;
    } else if cfg!(target_os = "windows") {
        // Windows
        let mut cmd = Command::new("clip");
        cmd.stdin(std::process::Stdio::piped());
        let mut child = cmd.spawn()?;
        {
            let stdin = child.stdin.as_mut().ok_or("Failed to open stdin")?;
            use std::io::Write;
            stdin.write_all(text.as_bytes())?;
        }
        child.wait()?;
    } else {
        // Linux 和其他类Unix系统
        // 尝试使用xclip
        if Command::new("xclip").arg("-version").output().is_ok() {
            let mut cmd = Command::new("xclip");
            cmd.arg("-selection").arg("clipboard");
            cmd.arg("-i");
            cmd.stdin(std::process::Stdio::piped());
            let mut child = cmd.spawn()?;
            {
                let stdin = child.stdin.as_mut().ok_or("Failed to open stdin")?;
                use std::io::Write;
                stdin.write_all(text.as_bytes())?;
            }
            child.wait()?;
        }
        // 尝试使用xsel
        else if Command::new("xsel").arg("--version").output().is_ok() {
            let mut cmd = Command::new("xsel");
            cmd.arg("--clipboard");
            cmd.arg("--input");
            cmd.stdin(std::process::Stdio::piped());
            let mut child = cmd.spawn()?;
            {
                let stdin = child.stdin.as_mut().ok_or("Failed to open stdin")?;
                use std::io::Write;
                stdin.write_all(text.as_bytes())?;
            }
            child.wait()?;
        }
        // 尝试使用wl-copy (Wayland)
        else if Command::new("wl-copy").arg("--version").output().is_ok() {
            let mut cmd = Command::new("wl-copy");
            cmd.stdin(std::process::Stdio::piped());
            let mut child = cmd.spawn()?;
            {
                let stdin = child.stdin.as_mut().ok_or("Failed to open stdin")?;
                use std::io::Write;
                stdin.write_all(text.as_bytes())?;
            }
            child.wait()?;
        }
        else {
            return Err("没有可用的剪贴板工具。请安装 xclip, xsel 或 wl-copy".into());
        }
    }
    
    Ok(())
}

// 命令行模式下复制验证码到剪贴板
fn copy_to_clipboard_cli(code: &str) -> Result<(), Box<dyn Error>> {
    copy_to_clipboard_system(code)?;
    println!("验证码已复制到剪贴板: {}", code);
    Ok(())
}

fn run_tui<B: Backend>(terminal: &mut Terminal<B>, mut app: TuiApp) -> io::Result<()> {
    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(100);
    
    loop {
        terminal.draw(|f| {
            // 在渲染前检查是否需要更新验证码
            app.check_and_update_code();
            ui(f, &mut app)
        })?;
        
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));
            
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match app.current_screen {
                        Screen::Main => match key.code {
                            KeyCode::Esc => {
                                app.should_quit = true;
                            }
                            KeyCode::Char('Q') | KeyCode::Char('q') => {
                                // 修复：按下q键进入QR码导入界面，而不是退出
                                app.current_screen = Screen::AddKeyQr;
                                app.input_mode = InputMode::Editing;
                                app.input_buffer.clear();
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                app.next();
                            }
                            KeyCode::Up | KeyCode::Char('k') => {
                                app.previous();
                            }
                            KeyCode::Char('a') => {
                                app.current_screen = Screen::AddKey;
                                app.input_mode = InputMode::Editing;
                                app.input_buffer.clear();
                            }
                            KeyCode::Char('r') => {
                                app.remove_selected_key();
                            }
                            KeyCode::Char('g') => {
                                app.current_screen = Screen::GenerateQr;
                                app.input_mode = InputMode::Editing;
                                app.input_buffer.clear();
                            }
                            KeyCode::Char('c') => {
                                // 复制验证码到剪贴板
                                app.copy_to_clipboard();
                            }
                            _ => {}
                        },
                        Screen::AddKey | Screen::AddKeyQr | Screen::GenerateQr => match key.code {
                            KeyCode::Enter => {
                                match app.current_screen {
                                    Screen::AddKey => {
                                        let name = app.input_buffer.trim().to_string();
                                        if !name.is_empty() {
                                            let key = generate_key();
                                            app.add_key(name, key);
                                            app.current_screen = Screen::Main;
                                            app.input_mode = InputMode::Normal;
                                        }
                                    }
                                    Screen::AddKeyQr => {
                                        let path = app.input_buffer.trim().to_string();
                                        if !path.is_empty() {
                                            match decode_qr_code(&path) {
                                                Ok(otpauth_uri) => {
                                                    match parse_otpauth_uri(&otpauth_uri) {
                                                        Ok(params) => {
                                                            let name = if let (Some(issuer), Some(account)) = (&params.issuer, &params.account) {
                                                                format!("{}:{}", issuer, account)
                                                            } else if let Some(account) = &params.account {
                                                                account.clone()
                                                            } else {
                                                                "unknown".to_string()
                                                            };
                                                            app.add_key(name, Zeroizing::new(params.secret));
                                                        }
                                                        Err(e) => {
                                                            app.show_message(format!("解析URI失败: {}", e), Duration::from_secs(3));
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    app.show_message(format!("解码QR码失败: {}", e), Duration::from_secs(3));
                                                }
                                            }
                                            app.current_screen = Screen::Main;
                                            app.input_mode = InputMode::Normal;
                                        }
                                    }
                                    Screen::GenerateQr => {
                                        let input = app.input_buffer.trim().to_string();
                                        let parts: Vec<&str> = input.split_whitespace().collect();
                                        if parts.len() == 3 {
                                            let name = parts[0];
                                            let issuer = parts[1];
                                            let output_path = parts[2];
                                            
                                            if let Some(key) = app.app.get_key(name) {
                                                if let Err(e) = generate_qr_code(&key, name, issuer, output_path) {
                                                    app.show_message(format!("生成QR码失败: {}", e), Duration::from_secs(3));
                                                } else {
                                                    app.show_message("QR码已生成".to_string(), Duration::from_secs(2));
                                                }
                                            } else {
                                                app.show_message(format!("未找到密钥: {}", name), Duration::from_secs(3));
                                            }
                                            app.current_screen = Screen::Main;
                                            app.input_mode = InputMode::Normal;
                                        } else {
                                            app.show_message("格式: 名称 发行商 输出路径".to_string(), Duration::from_secs(3));
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            KeyCode::Esc => {
                                app.current_screen = Screen::Main;
                                app.input_mode = InputMode::Normal;
                            }
                            KeyCode::Char(c) => {
                                app.input_buffer.push(c);
                            }
                            KeyCode::Backspace => {
                                app.input_buffer.pop();
                            }
                            _ => {}
                        },
                        _ => {}
                    }
                }
            }
        }
        
        // 检查消息计时器
        app.check_message_timer();
        
        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
        
        if app.should_quit {
            return Ok(());
        }
    }
}

fn ui<B: Backend>(f: &mut Frame<B>, app: &mut TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(3),
            ]
            .as_ref(),
        )
        .split(f.size());
    
    // 标题
    let title = Paragraph::new("TOTP认证管理器")
        .style(Style::default().add_modifier(Modifier::BOLD))
        .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(title, chunks[0]);
    
    // 主内容区域
    match app.current_screen {
        Screen::Main => render_main_screen(f, app, chunks[1]),
        Screen::AddKey => render_input_screen(f, app, chunks[1], "输入新密钥名称:"),
        Screen::AddKeyQr => render_input_screen(f, app, chunks[1], "输入QR码图像路径:"),
        Screen::GenerateQr => render_input_screen(f, app, chunks[1], "输入: 名称 发行商 输出路径"),
        _ => render_main_screen(f, app, chunks[1]),
    }
    
    // 底部状态栏
    let status = match app.current_screen {
        Screen::Main => {
            let keys: Vec<&String> = app.app.list_keys();
            if keys.is_empty() {
                "按 'a' 添加密钥, 'Esc' 退出".to_string()
            } else {
                format!("↑↓ 选择, 'a' 添加, 'r' 删除, 'q' QR码, 'g' 生成QR码, 'c' 复制验证码, 'Esc' 退出 | 剩余时间: {}秒", app.remaining_time)
            }
        }
        Screen::AddKey => "输入密钥名称并按 Enter 确认, Esc 取消".to_string(),
        Screen::AddKeyQr => "输入QR码图像路径并按 Enter 确认, Esc 取消".to_string(),
        Screen::GenerateQr => "输入: 名称 发行商 输出路径, 按 Enter 确认, Esc 取消".to_string(),
        _ => "".to_string(),
    };
    
    let status_bar = Paragraph::new(status)
        .style(Style::default().add_modifier(Modifier::REVERSED))
        .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(status_bar, chunks[2]);
    
    // 显示消息
    if let Some(message) = &app.message {
        let area = centered_rect(60, 20, f.size());
        let block = Block::default()
            .title("消息")
            .borders(Borders::ALL)
            .style(Style::default().bg(Color::LightBlue));
        let paragraph = Paragraph::new(message.as_str())
            .wrap(ratatui::widgets::Wrap { trim: true })
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(block, area);
        f.render_widget(paragraph, area.inner(&ratatui::layout::Margin::new(1, 1)));
    }
}

fn render_main_screen<B: Backend>(f: &mut Frame<B>, app: &mut TuiApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(area);
    
    // 左侧：密钥列表
    let keys: Vec<&String> = app.app.list_keys();
    let items: Vec<ListItem> = keys
        .iter()
        .map(|k| {
            let content = Line::from(Span::raw(*k));
            ListItem::new(content)
        })
        .collect();
    
    let list = List::new(items)
        .block(Block::default().title("密钥列表").borders(Borders::ALL))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol(">> ");
    
    f.render_stateful_widget(list, chunks[0], &mut app.list_state);
    
    // 右侧：当前验证码
    let code_block = Block::default().title("当前验证码").borders(Borders::ALL);
    let inner_area = code_block.inner(chunks[1]);
    
    let code_text = if let Some(code) = &app.current_code {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
            .split(inner_area);
        
        // 大型验证码显示
        let code_display = Paragraph::new(code.as_str())
            .style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
            .alignment(ratatui::layout::Alignment::Center)
            .block(Block::default());
        f.render_widget(code_display, chunks[0]);
        
        // 剩余时间进度条
        let remaining = app.remaining_time as f64 / 30.0;
        let progress = ((1.0 - remaining) * inner_area.width as f64) as u16;
        
        let progress_bar = Paragraph::new("▰".repeat(progress as usize))
            .style(Style::default().fg(Color::Green))
            .alignment(ratatui::layout::Alignment::Left);
        f.render_widget(progress_bar, chunks[1]);
        
        Line::from(vec![
            Span::styled(code.as_str(), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::raw(format!(" ({}秒)", app.remaining_time)),
        ])
    } else {
        Line::from(Span::raw("没有选择密钥"))
    };
    
    let code_paragraph = Paragraph::new(code_text).block(code_block);
    f.render_widget(code_paragraph, chunks[1]);
}

fn render_input_screen<B: Backend>(f: &mut Frame<B>, app: &mut TuiApp, area: Rect, prompt: &str) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(3)].as_ref())
        .split(area);
    
    let prompt_paragraph = Paragraph::new(prompt)
        .style(Style::default().add_modifier(Modifier::BOLD))
        .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(prompt_paragraph, chunks[0]);
    
    let input_block = Block::default().borders(Borders::ALL).title("输入");
    let input_paragraph = Paragraph::new(app.input_buffer.as_str())
        .style(match app.input_mode {
            InputMode::Normal => Style::default(),
            InputMode::Editing => Style::default().fg(Color::Yellow),
        })
        .block(input_block);
    f.render_widget(input_paragraph, chunks[1]);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);
    
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}

fn main() -> Result<(), Box<dyn Error>> {
    // 检查命令行参数
    let args: Vec<String> = env::args().collect();
    
    // 如果有参数，使用命令行模式
    if args.len() > 1 {
        return run_cli_mode();
    }
    
    // 否则启动TUI模式
    run_tui_mode()
}

fn run_cli_mode() -> Result<(), Box<dyn Error>> {
    let mut app = App::load()?;
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }
    
    match args[1].as_str() {
        "add" => {
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
            if args.len() < 3 {
                eprintln!("需要提供QR码图像路径");
                process::exit(1);
            }
            
            let image_path = &args[2];
            
            let otpauth_uri = decode_qr_code(image_path)?;
            println!("解码的URI: {}", otpauth_uri);
            
            let params = parse_otpauth_uri(&otpauth_uri)?;
            
            let name = if let (Some(issuer), Some(account)) = (&params.issuer, &params.account) {
                format!("{}:{}", issuer, account)
            } else if let Some(account) = &params.account {
                account.clone()
            } else {
                return Err("无法从QR码确定账户名称".into());
            };
            
            app.add_key(name.clone(), Zeroizing::new(params.secret));
            app.save()?;
            
            println!("已从QR码添加密钥: {}", name);
        }
        "generate-qr" => {
            if args.len() < 5 {
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
            if args.len() < 3 {
                eprintln!("需要提供名称参数");
                process::exit(1);
            }
            
            let name = &args[2];
            
            if let Some(key) = app.get_key(name) {
                let code = calculate_totp(&key, Local::now())?;
                println!("{} 的验证码: {}", name, code);
                
                // 命令行模式下也支持复制到剪贴板
                if args.len() > 3 && args[3] == "--copy" {
                    copy_to_clipboard_cli(&code)?;
                }
            } else {
                eprintln!("未找到 '{}' 的密钥", name);
                process::exit(1);
            }
        }
        "list" => {
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
            let window = get_time_window(1);
            println!("当前时间窗口: {} 到 {}", window.start, window.end);
            
            let now = Local::now();
            let remaining = (window.end - now).num_seconds();
            println!("剩余时间: {} 秒", remaining);
        }
        "generate-codes" => {
            if args.len() < 3 {
                eprintln!("需要提供名称参数");
                process::exit(1);
            }
            
            let name = &args[2];
            
            if let Some(key) = app.get_key(name) {
                let window: u64 = 1;
                
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
        "tui" => {
            // 启动TUI模式
            run_tui_mode()?;
        }
        _ => {
            eprintln!("未知命令: {}", args[1]);
            print_usage();
            process::exit(1);
        }
    }
    
    Ok(())
}

fn run_tui_mode() -> Result<(), Box<dyn Error>> {
    // 初始化终端
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    
    // 创建应用实例
    let app = App::load()?;
    let tui_app = TuiApp::new(app);
    
    // 运行应用
    let res = run_tui(&mut terminal, tui_app);
    
    // 恢复终端
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    
    if let Err(err) = res {
        println!("{:?}", err);
    }
    
    Ok(())
}

fn print_usage() {
    println!("用法: auther <命令> [参数]");
    println!();
    println!("命令:");
    println!("  add <名称>             添加新密钥");
    println!("  add-qr <二维码路径>     从QR码图像添加密钥");
    println!("  generate-qr <名称> <发行商> <输出路径> 为现有密钥生成QR码");
    println!("  get <名称> [--copy]    获取当前TOTP码（可选复制到剪贴板）");
    println!("  list                   列出所有存储的密钥");
    println!("  remove <名称>          删除密钥");
    println!("  time-window            显示当前时间窗口信息");
    println!("  generate-codes <名称>  生成当前时间窗口及其前后窗口的TOTP码");
    println!("  tui                    启动文本用户界面(TUI)模式");
    println!();
    println!("TUI模式快捷键:");
    println!("  ↑/k, ↓/j   上下选择账户");
    println!("  a          添加新密钥");
    println!("  r          删除当前密钥");
    println!("  q          从QR码图像添加密钥");
    println!("  g          为当前密钥生成QR码");
    println!("  c          复制当前验证码到剪贴板");
    println!("  Esc        退出");
    println!();
    println!("如果不带参数运行，将自动启动TUI模式");
}
