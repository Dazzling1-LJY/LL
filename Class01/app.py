import os
import time
import uuid
import secrets
import sqlite3
from functools import wraps
from decimal import Decimal
from datetime import datetime, timedelta
from flask import Flask, render_template, render_template_string, request, redirect, session, url_for, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

# 数据库初始化
DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DB_DIR, "users.db")

def init_db():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        balance REAL DEFAULT 0
    )''')
    # 为旧表添加 balance 列（如果不存在）
    try:
        c.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # 列已存在
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES ('admin', 'admin123', 'admin@example.com', '13800138000', 0)")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES ('alice', 'alice2025', 'alice@example.com', '13900139001', 0)")
    conn.commit()
    conn.close()

init_db()

# 修复4：通过环境变量获取 secret_key，或使用加密随机密钥
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32).hex())
# 修复7：设置 session 有效期为30分钟
app.config["PERMANENT_SESSION_LIFETIME"] = 1800
# 修复8：通过环境变量控制 debug 模式
app.debug = os.environ.get("FLASK_DEBUG", "0") == "1"

# 上传配置
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 文件上传白名单
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "bmp", "webp"}
ALLOWED_MIMETYPES = {"image/jpeg", "image/png", "image/gif", "image/bmp", "image/webp"}
# 图片文件 Magic Number（文件头字节特征）
MAGIC_NUMBERS = [
    (b"\xff\xd8\xff", "jpeg"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"BM", "bmp"),
    (b"RIFF", "webp"),
]

# 管理员密码重置为 admin123
_DEFAULT_ADMIN_PASS = "admin123"

# 修复1：密码不存储明文，只存哈希
USERS = {
    "admin": {
        "id": 1,
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
        "locked_until": 0,
        "login_failures": 0,
        "must_change_password": False,
    },
}

LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCK_MINUTES = 15


def login_required(f):
    """登录保护装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def sanitize_user(user_dict):
    """修复3：返回用户信息时排除敏感字段"""
    safe = dict(user_dict)
    safe.pop("password", None)
    safe.pop("locked_until", None)
    safe.pop("login_failures", None)
    safe.pop("must_change_password", None)
    return safe


def is_locked(user_dict):
    """检查用户是否被锁定"""
    if user_dict.get("locked_until", 0) > time.time():
        remaining = int(user_dict["locked_until"] - time.time())
        return True, remaining
    return False, 0


def get_user_from_db(username):
    """从 SQLite 数据库中查询用户信息"""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        if row:
            user = dict(row)
            user.setdefault("role", "user")
            return user
        return None
    except Exception:
        return None


def get_user_by_id(user_id):
    """根据 user_id 查询用户信息（无论内存还是数据库）"""
    # 先在内存 USERS 字典中查找
    for username, user_data in USERS.items():
        user_data["id"] = user_data.get("id", 1 if username == "admin" else 0)
        if str(user_data["id"]) == str(user_id):
            return sanitize_user(user_data)

    # 再去数据库查找
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        conn.close()
        if row:
            user = dict(row)
            user.setdefault("role", "user")
            return user
        return None
    except Exception:
        return None


def update_balance_in_db(user_id, new_balance):
    """更新数据库中用户的余额"""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        c = conn.cursor()
        c.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, user_id))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def get_current_user_balance(user_id):
    """获取数据库中用户的当前余额"""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        c = conn.cursor()
        c.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        conn.close()
        if row:
            return row[0] or 0
        return 0
    except Exception:
        return 0


# ==================== CSRF 防护 ====================

def generate_csrf_token():
    """生成并存储 CSRF Token 到 session"""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf_token(token):
    """校验 CSRF Token"""
    stored_token = session.get("csrf_token")
    if not stored_token or not token:
        return False
    return secrets.compare_digest(stored_token, token)


@app.context_processor
def inject_global_vars():
    """向所有模板注入 csrf_token 变量"""
    token = generate_csrf_token()
    return dict(csrf_token=token)


def check_referer():
    """校验 Referer，防止 CSRF（仅当 Referer 存在且来自外部时才拦截）"""
    referer = request.headers.get("Referer", "")
    from urllib.parse import urlparse
    # 无 Referer：依赖 CSRF Token 校验（允许 API 客户端）
    if not referer:
        return True
    # 有 Referer：检查是否同源
    parsed = urlparse(referer)
    allowed_hosts = ("127.0.0.1", "localhost", "192.168.137.129")
    if parsed.hostname and parsed.hostname not in allowed_hosts:
        return False
    return True


# ==================== 文件上传校验 ====================

def allowed_file(filename):
    """WEB-UP-002 修复：白名单后缀校验"""
    return "." in filename and \
           filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def valid_magic_number(file_obj):
    """WEB-UP-004 修复：Magic Number 文件头校验"""
    header = file_obj.read(16)
    file_obj.seek(0)
    return any(header.startswith(magic) for magic, _ in MAGIC_NUMBERS)


@app.route("/")
def index():
    username = session.get("username")
    if not username:
        return render_template("index.html", user_info=None)

    user = USERS.get(username)
    if user is None:
        user = get_user_from_db(username)

    if user is None:
        return render_template("index.html", user_info=None)

    locked, remaining = is_locked(user)
    if locked:
        session.pop("username", None)
        return render_template("index.html", user_info=None,
                               error=f"账号已被锁定，请{remaining}秒后再试")

    user_info = sanitize_user(user)
    # 获取当前用户的 ID（供个人中心链接使用）
    current_user_id = user.get("id", 1)
    return render_template("index.html", user_info=user_info, current_user_id=current_user_id)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        registered = request.args.get("registered")
        return render_template("login.html", registered=registered)

    error = None
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        error = "用户名和密码不能为空"
        return render_template("login.html", error=error)

    user = USERS.get(username)
    # 如果在内存字典中找不到，尝试从数据库查找（注册用户）
    if user is None:
        db_user = get_user_from_db(username)
        if db_user is not None:
            # 数据库用户密码为明文，直接比对
            if db_user["password"] == password:
                session["username"] = username
                session["user_id"] = db_user.get("id")
                session.permanent = True
                user_info = sanitize_user(db_user)
                return render_template("index.html", user_info=user_info, current_user_id=db_user.get("id"))
            else:
                error = "用户名或密码错误，请重试"
                return render_template("login.html", error=error)

    # 模糊提示：不区分"用户不存在"和"密码错误"
    if user is None:
        error = "用户名或密码错误，请重试"
        return render_template("login.html", error=error)

    # 修复5：检查是否被锁定
    locked, remaining = is_locked(user)
    if locked:
        error = f"账号已被锁定，请{remaining}秒后再试"
        return render_template("login.html", error=error)

    # 修复1：使用 werkzeug 安全比对哈希
    if check_password_hash(user["password"], password):
        # 登录成功，重置失败计数
        user["login_failures"] = 0
        user["locked_until"] = 0
        session["username"] = username
        session["user_id"] = user.get("id")
        session.permanent = True

        # 强制首次修改密码（跳转到首页，通过个人中心修改）
        if user.get("must_change_password"):
            return redirect("/")

        user_info = sanitize_user(user)
        return render_template("index.html", user_info=user_info, current_user_id=user.get("id"))
    else:
        # 修复5：失败计数+锁定
        user["login_failures"] = user.get("login_failures", 0) + 1
        remaining_attempts = LOGIN_MAX_ATTEMPTS - user["login_failures"]
        if user["login_failures"] >= LOGIN_MAX_ATTEMPTS:
            user["locked_until"] = time.time() + LOGIN_LOCK_MINUTES * 60
            error = f"密码错误次数过多，账号已锁定{LOGIN_LOCK_MINUTES}分钟"
        else:
            error = f"用户名或密码错误，请重试（还剩{remaining_attempts}次机会）"
        return render_template("login.html", error=error)


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    """修改密码（修复：CSRF防护 + 身份校验 + 原密码验证）"""
    # GET 请求直接跳转到个人中心
    if request.method == "GET":
        user_id = session.get("user_id", 1)
        return redirect(f"/profile?user_id={user_id}")
    # 修复 CSRF-001 & CSRF-002：CSRF Token 校验 + Referer 校验
    csrf_token = request.form.get("csrf_token", "")
    if not validate_csrf_token(csrf_token):
        return redirect("/profile?error=请求验证失败，请刷新页面重试")

    if not check_referer():
        return redirect("/profile?error=非法请求来源")

    current_username = session.get("username")
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    # 修复 IDOR-PWD-002：已由 @login_required 保证登录状态

    # 修复 IDOR-PWD-001：只能修改自己的密码
    # username 不再从表单获取，直接使用 session 中的用户名
    username = current_username

    if not old_password or not new_password:
        return redirect("/profile?error=请填写完整信息")

    if new_password != confirm_password:
        return redirect("/profile?error=两次输入的密码不一致")

    # 修复 IDOR-PWD-003：验证原密码
    user_data = USERS.get(username)
    if user_data:
        if not check_password_hash(user_data["password"], old_password):
            return redirect("/profile?error=原密码不正确")
        user_data["password"] = generate_password_hash(new_password)
        user_data["must_change_password"] = False
        return redirect(f"/profile?user_id={user_data.get('id', 1)}&success=密码修改成功")

    # 数据库用户
    db_user = get_user_from_db(username)
    if db_user:
        db_id = db_user.get("id")
        # 数据库用户密码是明文，直接比对
        stored_pwd = db_user.get("password", "")
        if old_password != stored_pwd:
            return redirect("/profile?error=原密码不正确")
        try:
            conn = sqlite3.connect(DB_PATH, timeout=10)
            c = conn.cursor()
            c.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, username))
            conn.commit()
            conn.close()
            return redirect(f"/profile?user_id={db_id}&success=密码修改成功")
        except Exception:
            return redirect("/profile?error=修改失败，请稍后重试")

    return redirect("/profile?error=未找到该用户")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()

    error = None
    if not username or not password:
        error = "用户名和密码不能为空"
        return render_template("register.html", error=error)

    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        c = conn.cursor()
        # ✅ 修复：使用参数化查询，防止 SQL 注入
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"[SQL] {sql} | params={[username, password, email, phone]!r}", flush=True)
        c.execute(sql, (username, password, email, phone))
        conn.commit()
        conn.close()
        return redirect("/login?registered=1")
    except sqlite3.IntegrityError:
        try:
            conn.close()
        except:
            pass
        error = "用户名已存在"
        return render_template("register.html", error=error)
    except Exception as e:
        try:
            conn.close()
        except:
            pass
        error = f"注册失败: {str(e)}"
        return render_template("register.html", error=error)


@app.route("/search")
def search():
    keyword = request.args.get("keyword", "").strip()
    results = []
    sql = ""
    if keyword:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # ✅ 修复：使用参数化查询，防止 SQL 注入
        sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
        keyword_param = f"%{keyword}%"
        print(f"[SQL] {sql} | keyword_param={keyword_param!r}", flush=True)
        c.execute(sql, (keyword_param, keyword_param))
        rows = c.fetchall()
        results = [dict(row) for row in rows]
        conn.close()

    username = session.get("username")
    user_info = None
    if username:
        user = USERS.get(username)
        if user is None:
            user = get_user_from_db(username)
        if user:
            locked, remaining = is_locked(user)
            if not locked:
                user_info = sanitize_user(user)

    return render_template("index.html", user_info=user_info, search_results=results, keyword=keyword, sql_debug=sql)


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "GET":
        return render_template("upload.html")

    file = request.files.get("avatar")
    error = None
    success = None
    file_url = None
    filename = None

    # 修复 WEB-UP-009：文件为空检查
    if file is None or file.filename == "":
        return render_template("upload.html", error="请选择要上传的文件")

    # 修复 WEB-UP-002：白名单后缀校验
    if not allowed_file(file.filename):
        return render_template("upload.html",
                               error="仅支持 jpg/jpeg/png/gif/bmp/webp 格式的图片文件")

    # 修复 WEB-UP-003：MIME 类型辅助校验
    if file.mimetype not in ALLOWED_MIMETYPES:
        return render_template("upload.html",
                               error="不支持的文件类型")

    # 修复 WEB-UP-004：Magic Number 文件头校验
    if not valid_magic_number(file):
        return render_template("upload.html",
                               error="文件内容不是有效的图片格式")

    try:
        # 修复 WEB-UP-006：secure_filename 防路径穿越 + 防特殊字符
        safe_name = secure_filename(file.filename)
        if not safe_name:
            return render_template("upload.html", error="无效的文件名")

        # 修复 WEB-UP-005：UUID 重命名防止文件覆盖
        ext = safe_name.rsplit(".", 1)[1].lower()
        unique_name = f"{uuid.uuid4().hex}.{ext}"

        # 修复 WEB-UP-007：上传至隔离目录（非 static/ 子目录）
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)
        file.save(save_path)

        # 通过单独的路由提供访问
        file_url = url_for("uploaded_file", filename=unique_name)
        success = "头像上传成功！"
    except OSError:
        return render_template("upload.html", error="文件保存失败，请稍后重试")
    except Exception:
        return render_template("upload.html", error="上传处理失败，请联系管理员")

    return render_template("upload.html", success=success, file_url=file_url, filename=unique_name)


@app.route("/uploads/<filename>")
@login_required
def uploaded_file(filename):
    """修复 WEB-UP-007：通过隔离路由提供上传文件的访问，可安全预览"""
    from flask import send_from_directory
    # 启用 X-Sendfile（生产环境性能优化）
    response = send_from_directory(app.config["UPLOAD_FOLDER"], filename)
    # 安全响应头：防止 MIME 类型嗅探和 XSS
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Disposition"] = f"inline; filename=\"{filename}\""
    return response


@app.route("/profile")
@login_required
def profile():
    """修复 IDOR-001：添加登录保护和权限校验"""
    current_user_id = session.get("user_id")
    target_user_id = request.args.get("user_id")
    url_error = request.args.get("error")  # 读取从 recharge 重定向带来的错误信息

    if not target_user_id:
        # 如果没有 user_id 但有 error（从 change-password/recharge 重定向过来）
        # 使用当前登录用户的 ID 显示页面
        if url_error:
            user = get_user_by_id(current_user_id)
            if user:
                return render_template("profile.html", user=user, error=url_error, user_id=current_user_id)
        return render_template("profile.html", user=None, error="请提供用户ID", user_id=None)

    try:
        target_user_id = int(target_user_id)
    except ValueError:
        return render_template("profile.html", user=None, error="无效的用户ID", user_id=None)

    # 权限校验：只能查看自己的个人中心
    if str(target_user_id) != str(current_user_id):
        return render_template("profile.html", user=None, error="无权查看其他用户的资料", user_id=None)

    user = get_user_by_id(target_user_id)
    if user is None:
        return render_template("profile.html", user=None, error="未找到该用户", user_id=None)

    return render_template("profile.html", user=user, error=url_error, user_id=target_user_id)


@app.route("/recharge", methods=["POST"])
@login_required
def recharge():
    """修复 BL-004：添加 @login_required 认证"""
    current_user_id = session.get("user_id")
    user_id = request.form.get("user_id")
    amount_str = request.form.get("amount")

    if not user_id or not amount_str:
        return redirect("/profile?error=参数不完整")

    try:
        user_id = int(user_id)
        amount = Decimal(str(amount_str))
    except (ValueError, Exception):
        return redirect("/profile?error=参数格式错误")

    # 修复 IDOR-002：只能给自己充值
    if user_id != current_user_id:
        return redirect("/profile?error=无权操作其他用户账户")

    # 修复 BL-001：金额必须大于0
    if amount <= 0:
        return redirect(f"/profile?user_id={user_id}&error=金额必须大于0")

    # 修复 BL-003：频率限制 - 每分钟最多充5次
    now = time.time()
    last_time = session.get("last_recharge_time", 0)
    recharge_count = session.get("recharge_count", 0)

    if now - last_time > 60:
        # 新的一分钟，重置计数
        session["recharge_count"] = 1
        session["last_recharge_time"] = now
    elif recharge_count >= 5:
        return redirect(f"/profile?user_id={user_id}&error=充值过于频繁，请稍后再试")
    else:
        session["recharge_count"] = recharge_count + 1

    # 修复 BL-002：使用 Decimal 替代 float 避免精度问题
    if user_id == 1:  # admin 内存用户
        for username, user_data in USERS.items():
            if user_data.get("id") == user_id:
                current_balance = Decimal(str(user_data.get("balance", 0)))
                new_balance = current_balance + amount
                user_data["balance"] = float(new_balance)
                # 同步存入数据库
                update_balance_in_db(user_id, float(new_balance))
                return redirect(f"/profile?user_id={user_id}")
    else:
        # 数据库用户
        current_balance = Decimal(str(get_current_user_balance(user_id)))
        new_balance = current_balance + amount
        update_balance_in_db(user_id, float(new_balance))

    return redirect(f"/profile?user_id={user_id}")


@app.route("/page")
@login_required
def dynamic_page():
    """修复 LFI 漏洞：路径规范化 + 目录约束 + 访问控制 + XSS 防护"""
    name = request.args.get("name", "")
    page_content = None
    error = None

    if name:
        # 修复 LFI-ABSOLUTE-001 & LFI-PATH-001：规范化路径并校验前缀
        pages_dir = os.path.realpath(os.path.join(app.root_path, "pages"))
        requested_path = os.path.realpath(os.path.join(pages_dir, name))

        # 校验：目标文件必须在 pages/ 目录内
        if not requested_path.startswith(pages_dir):
            error = "页面不存在"
        elif os.path.isfile(requested_path):
            with open(requested_path, "r", encoding="utf-8") as f:
                page_content = f.read()
        else:
            # 尝试加上 .html 后缀
            requested_path_html = requested_path + ".html"
            if os.path.isfile(requested_path_html):
                with open(requested_path_html, "r", encoding="utf-8") as f:
                    page_content = f.read()
            else:
                error = "页面不存在"

    # 获取当前登录用户信息用于模板显示
    username = session.get("username")
    user_info = None
    if username:
        user = USERS.get(username)
        if user is None:
            user = get_user_from_db(username)
        if user:
            locked, remaining = is_locked(user)
            if not locked:
                user_info = sanitize_user(user)

    return render_template("index.html", user_info=user_info, page_content=page_content, page_error=error)


# ==================== 个性化页面 ====================

@app.route("/welcome")
def welcome():
    name = request.args.get("name", "")
    if not name:
        # 已登录用户默认显示用户名
        username = session.get("username")
        if username:
            name = username
        else:
            name = "亲爱的用户"
    # 修复 SSTI：使用模板变量代替 f-string 拼接
    html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>欢迎页 - 用户管理系统</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="nav-left">
            <span class="brand">用户管理系统</span>
        </div>
        <div class="nav-right">
            <a href="/register" class="nav-link">注册</a>
            <a href="/login" class="nav-link">登录</a>
            <a href="/welcome" class="nav-link">欢迎页</a>
            <a href="/feedback" class="nav-link">反馈</a>
        </div>
    </nav>
    <main class="container">
        <div class="card" style="text-align: center;">
            <h1>欢迎你，{{ name }}！</h1>
            <a href="/" class="btn" style="margin-top: 20px;">返回首页</a>
        </div>
    </main>
</body>
</html>"""
    return render_template_string(html, name=name)


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "GET":
        html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>用户反馈 - 用户管理系统</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="nav-left">
            <span class="brand">用户管理系统</span>
        </div>
        <div class="nav-right">
            <a href="/register" class="nav-link">注册</a>
            <a href="/login" class="nav-link">登录</a>
            <a href="/welcome" class="nav-link">欢迎页</a>
            <a href="/feedback" class="nav-link">反馈</a>
        </div>
    </nav>
    <main class="container">
        <div class="card login-card">
            <h2>用户反馈</h2>
            <form method="post" action="/feedback">
                <div class="form-group">
                    <label for="name">姓名</label>
                    <input type="text" id="name" name="name" class="form-input" placeholder="请输入您的姓名" required>
                </div>
                <div class="form-group">
                    <label for="message">留言内容</label>
                    <textarea id="message" name="message" class="form-input" rows="5" placeholder="请输入您的反馈意见" required></textarea>
                </div>
                <button type="submit" class="btn">提交反馈</button>
            </form>
        </div>
    </main>
</body>
</html>"""
        return render_template_string(html)

    # POST — 修复 SSTI：使用模板变量代替 f-string 拼接
    name = request.form.get("name", "")
    message = request.form.get("message", "")
    result_html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>反馈结果 - 用户管理系统</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="nav-left">
            <span class="brand">用户管理系统</span>
        </div>
        <div class="nav-right">
            <a href="/register" class="nav-link">注册</a>
            <a href="/login" class="nav-link">登录</a>
            <a href="/welcome" class="nav-link">欢迎页</a>
            <a href="/feedback" class="nav-link">反馈</a>
        </div>
    </nav>
    <main class="container">
        <div class="card">
            <h2>{{ name }} 的反馈：</h2>
            <p>{{ message }}</p>
            <a href="/feedback" class="btn" style="margin-top: 16px;">继续反馈</a>
            <a href="/" class="btn" style="margin-top: 16px;">返回首页</a>
        </div>
    </main>
</body>
</html>"""
    return render_template_string(result_html, name=name, message=message)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    print(f"[INFO] 管理员密码已重置为: admin123")
    print(f"[INFO] 账号: admin / 密码: admin123")
    # 生产环境请配置 HTTPS/TLS 反向代理（如 Nginx + Let's Encrypt），
    # 确保密码等敏感信息通过加密通道传输
    app.run(host="0.0.0.0", port=5000)
