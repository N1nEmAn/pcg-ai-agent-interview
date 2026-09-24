# 腾讯 PCG 二面 Web 安全学习笔记

> 当前进度：一面已通过。下一轮重点补 Web 基础，特别是“具体怎么修、代码怎么写、怎样验证修复有效”。  
> 学习目标：遇到每个漏洞，都能讲清 **原理 → 修复实现 → 验证证据 → 回归测试**。

---

## 0. 面试答题总公式

遇到任何 Web 漏洞，按五步回答：

1. **入口**：攻击者能控制哪个参数、请求或文件？
2. **危险点**：输入最终进入了什么危险操作？
3. **证据**：如何用请求、响应、状态变化、日志或代码证明？
4. **修复**：服务端具体改哪里？
5. **回归**：怎样证明漏洞消失且正常业务没坏？

不要只说“加强校验”“过滤特殊字符”。面试官想知道：**在哪里校验、校验什么、为什么能切断攻击链**。

---

## 1. HTTP、认证与授权

### 1.1 一条请求要看什么

~~~text
POST /api/orders/1002 HTTP/1.1
Host: shop.example
Cookie: session=...
Authorization: Bearer ...
Content-Type: application/json
Origin: https://shop.example

{"amount": 10, "url": "..."}
~~~

安全测试要观察：

- 方法：GET、POST、PUT、PATCH、DELETE；
- 路径参数和查询参数；
- Header、Cookie、Authorization；
- JSON、表单、XML、上传文件；
- 当前身份：普通用户、管理员、不同租户；
- 响应状态码、长度、字段、Header、时间和后续状态。

HTTP 方法只是约定，不能代替权限。接口使用 DELETE，服务端仍然必须检查身份和对象权限。

### 1.2 认证和授权

- **认证 Authentication**：你是谁？
- **授权 Authorization**：你能做什么？能操作哪个对象？

面试句：

> Cookie、Session 或 JWT 负责携带身份上下文，服务端还要在每次对象操作时检查用户、角色、租户、对象归属和资源状态。

### 1.3 Cookie 属性

| 属性 | 作用 | 不能解决什么 |
|---|---|---|
| HttpOnly | 限制 JavaScript 读取 Cookie | 不能阻止浏览器自动携带 |
| Secure | 只通过 HTTPS 发送 | 不能阻止服务端越权 |
| SameSite | 降低跨站请求携带 Cookie 的风险 | 不能代替 CSRF token |
| Domain/Path | 限制作用范围 | 不能代替对象级授权 |
| Max-Age/Expires | 控制生命周期 | 不能解决 Token 泄露后的所有问题 |

### 1.4 JWT

验证 JWT 时要检查：

- 签名和允许的算法；
- 密钥是否正确；
- exp、nbf 等时间；
- iss、aud 是否匹配服务配置；
- 撤销、轮换和重放策略；
- 当前用户是否有权访问具体对象。

签名正确只说明 token 没被修改，不等于当前操作一定有权限。

---

## 2. SQL 注入：重点掌握代码

### 2.1 原理

错误写法把用户输入拼接成 SQL 语法：

~~~python
# 错误：username 进入了 SQL 语法
sql = f"SELECT id FROM users WHERE username = '{username}'"
cursor.execute(sql)
~~~

根因不是简单的“没有过滤特殊字符”，而是：

> 不可信数据和 SQL 语法混在一起，数据库会重新解析输入中的特殊字符。

### 2.2 预编译为什么能防注入

普通字符串拼接的执行过程大致是：

```text
用户输入 → 拼进完整 SQL 字符串 → 数据库解析 SQL 结构和输入 → 执行
```

如果输入中包含引号、括号或其他 SQL 语法，拼接后的字符串会被数据库重新解析，输入就可能改变原来的查询结构。

预编译把过程拆成两个阶段：

```text
Prepare：数据库先解析固定 SQL 结构，? 是参数占位符
Bind：   驱动把用户输入作为独立参数传给占位符
Execute：数据库按已经确定的结构执行
```

例如：

```python
statement = conn.prepare(
    "SELECT id FROM users WHERE username = ?"
)
statement.bind(1, username)
statement.execute()
```

数据库已经在 `Prepare` 阶段确定了 `SELECT ... WHERE username = ?` 的语法结构。`username` 在 `Bind` 阶段只是一个值，即使里面包含引号或 SQL 片段，也不会重新变成查询语法。驱动通常会通过数据库协议传递参数并处理类型，不需要开发者自己给输入加引号或转义。

可以把它理解成填表：SQL 语句是已经印好的表格，用户输入只能填进指定的空格，不能把表格的标题和结构改掉。

面试时还要注意一个实现细节：有些驱动默认使用“客户端模拟预编译”，先在客户端拼接字符串，再发送给数据库；应确认驱动配置使用真正的服务端 prepared statement，或确认驱动的参数处理实现是安全的。预编译也只保护参数值，不能让用户直接决定表名、列名或 SQL 结构。

### 2.3 参数化查询

Python 常见写法：

~~~python
# 正确：SQL 结构和用户数据分开
sql = "SELECT id FROM users WHERE username = ?"
cursor.execute(sql, (username,))
row = cursor.fetchone()
~~~

MySQL 驱动常见写法：

~~~python
sql = "SELECT id, email FROM users WHERE username = %s"
cursor.execute(sql, (username,))
~~~

Java JDBC：

~~~java
String sql = "SELECT id FROM users WHERE username = ?";
PreparedStatement ps = connection.prepareStatement(sql);
ps.setString(1, username);
ResultSet rs = ps.executeQuery();
~~~

Node.js：

~~~javascript
const [rows] = await db.execute(
  "SELECT id, username FROM users WHERE username = ?",
  [username]
);
~~~

记住四点：

- 占位符由数据库驱动处理；
- 参数作为 execute 的参数传入；
- 不要先用字符串格式化再传给 execute；
- 不要自己给输入加引号。

### 2.4 参数化的局限

参数化主要处理“值”，通常不能直接处理：

- 动态表名；
- 动态列名；
- 动态排序字段；
- 动态 SQL 结构。

错误写法：

~~~python
sql = f"SELECT * FROM users ORDER BY {order_by}"
~~~

正确做法：服务端固定映射。

~~~python
ORDER_FIELDS = {
    "name": "username",
    "created": "created_at",
}

column = ORDER_FIELDS.get(order_key)
if column is None:
    raise ValueError("invalid order field")

sql = f"SELECT id, username FROM users ORDER BY {column}"
cursor.execute(sql)
~~~

这里的 f-string 只拼接服务端字典中的固定值，不能拼接原始用户输入。

### 2.5 数据库最小权限

应用账号只拥有业务需要的权限：

- 不使用 root 连接业务；
- 普通查询账号不拥有 DROP、FILE、SUPER 等权限；
- 读写账号分离；
- 不同服务尽量使用不同账号；
- 凭据放在安全的配置或密钥系统中。

### 2.6 错误回显

服务端日志保留详细错误，客户端只返回通用信息：

~~~python
try:
    result = cursor.execute(sql, params)
except DatabaseError:
    logger.exception("database query failed")
    return {"error": "internal error"}, 500
~~~

不要向客户端返回 SQL、堆栈、数据库地址和账号信息。

### 2.7 SQL 回归测试

修复后检查：

- 普通查询仍正常；
- 引号、括号、注释符等特殊输入只是普通字符串；
- 布尔差异和时间差异不再改变业务结果；
- 登录、搜索、分页、排序、筛选都覆盖；
- 动态排序只接受 allowlist 字段；
- 代码中没有绕过 ORM 的字符串拼接；
- 数据库账号权限符合最小权限。

### 2.8 30 秒回答

> SQL 注入的根因是把不可信输入通过字符串拼接变成 SQL 语法。查询值使用参数化或预编译，让输入始终作为数据；动态表名、列名和排序字段不能直接参数化，就使用服务端固定映射或严格白名单。数据库账号还要最小权限，错误信息不能向客户端回显。回归时覆盖特殊输入、登录搜索排序等路径，确认输入不会改变 SQL 结构。

---

## 3. XSS：不要只说“过滤”

### 3.1 三种类型

**反射型**：输入出现在当前响应中，用户访问特制链接时触发。

**存储型**：输入被保存，其他用户打开页面时触发。

**DOM 型**：前端 JavaScript 从 URL、Hash、postMessage 或存储读取数据，再写入 innerHTML、eval 等危险 sink。它不一定经过服务器。

### 3.2 危险和安全写法

~~~javascript
// 危险：把输入解析成 HTML
result.innerHTML = userInput;

// 安全：作为普通文本
result.textContent = userInput;
~~~

### 3.3 为什么要按上下文编码

浏览器对不同位置使用不同语法：

- HTML 文本；
- HTML 属性；
- URL；
- JavaScript 字符串；
- CSS；
- DOM API。

因此 HTML 编码不能直接代替 JavaScript 或 URL 编码。原则是：

> 在最终输出位置，按照那个位置的解析规则编码；优先使用安全模板和安全 DOM API。

### 3.4 修复和回归

修复：

- 模板默认转义；
- DOM 文本使用 textContent；
- URL 限制 scheme；
- 富文本使用经过审计的 Sanitizer；
- Cookie 设置 HttpOnly、Secure、合理 SameSite；
- CSP 作为辅助防护。

回归：

- 反射、存储、DOM 三条路径都测；
- HTML、属性、URL、JS 上下文分别测；
- 用唯一无害 marker 检查是否进入危险 sink；
- 确认 marker 只作为文本显示；
- 检查历史存量数据。

面试句：

> CSP 是浏览器端的辅助控制，策略可能不完整，也不能修复数据进入错误输出上下文的问题；根因修复仍然是安全 API 和正确的上下文编码。

---

## 4. IDOR/BOLA：认证成功仍然可能越权

### 4.1 验证步骤

准备用户 A、用户 B、管理员和不同租户。

先用 A 访问自己的对象：

~~~text
GET /api/orders/1001
Cookie: session=user_A
~~~

然后只替换对象 ID：

~~~text
GET /api/orders/1002
Cookie: session=user_A
~~~

如果 1002 属于 B，而 A 能读取、修改、删除或导出，就可能是 BOLA/IDOR。

要记录：

- A 访问自己对象的基线；
- A 访问 B 对象的响应；
- 状态码、响应字段、长度和时间；
- 是否发生修改、删除或导出；
- 审计日志；
- 不同角色和租户结果。

### 4.2 根因和修复

根因是服务端只检查：

~~~text
session 是否有效
~~~

没有检查：

~~~text
当前用户是否拥有这个对象
当前租户是否匹配
当前角色是否允许这个动作
资源当前状态是否允许这个操作
~~~

修复示例：

~~~python
def get_order(current_user, order_id):
    order = load_order(order_id)

    if order is None:
        raise NotFound()

    if order.tenant_id != current_user.tenant_id:
        raise Forbidden()

    if (
        order.owner_id != current_user.id
        and not current_user.is_admin
    ):
        raise Forbidden()

    return order
~~~

写操作也要重新检查，不能只在读取时检查。

### 4.3 常见错误

- 只在前端隐藏按钮；
- 换成 UUID 就认为安全；
- 只检查用户登录；
- 只保护页面，不保护 API；
- 只测 GET，不测 PATCH、DELETE、导出和批量接口。

### 4.4 30 秒回答

> 我会用 A、B 两个身份，先让 A 访问自己的对象，再只替换对象 ID 访问 B 的对象，比较响应内容、状态变化和日志，并覆盖读、改、删、导出和批量接口。根因是服务端缺少对象级授权。修复是在每次对象操作时校验用户、租户、角色和资源归属，UUID 和前端隐藏都不能替代授权。

---

## 5. SSRF：白名单只是开始

### 5.1 原理

服务端存在抓取 URL、图片导入、网页预览或 Webhook 功能。攻击者控制 URL 后，服务器替攻击者发起网络请求。

危险链：

~~~text
用户输入 URL
    ↓
服务端 HTTP 客户端
    ↓
内网、loopback、metadata 或其他不应访问的资源
    ↓
响应回流给攻击者或进入 Agent 上下文
~~~

### 5.2 安全验证

只在授权靶场做：

1. 搭建自己控制的 canary 服务；
2. 让目标功能请求 canary；
3. 通过 canary 日志的 request-id、来源、路径和时间证明服务端发起请求；
4. 使用本地 mock 私网服务、mock redirect 和 DNS 测试边界；
5. 不访问真实公司内网、云 metadata 或第三方系统。

公网 URL 能收到请求，只证明存在服务端请求行为。还要判断它是否突破了产品预期访问范围。

### 5.3 修复措施

- 限制 scheme、host、端口；
- 使用出站 allowlist；
- DNS 解析后检查真实 IPv4/IPv6；
- 阻断 loopback、私网、链路本地和云 metadata；
- 防 DNS rebinding；
- 重定向逐跳重新解析和检查，或直接禁用；
- 限制响应大小、响应类型、超时和重定向次数；
- 从网络出口层限制访问；
- 不把完整内网响应直接送入模型上下文；
- Agent 工具和凭据使用最小权限。

### 5.4 回归测试

覆盖：

~~~text
127.0.0.1
IPv6 loopback
私网地址
链路本地地址
域名解析变化
重定向
编码形式
非 HTTP scheme
不同端口
超大响应
~~~

不能只做字符串黑名单。字符串判断容易被 IPv6、编码、DNS rebinding 和重定向绕过。

### 5.5 30 秒回答

> SSRF 是服务端替用户访问攻击者控制的 URL。验证时我会在授权环境用 canary 和 mock 私网服务证明服务端请求原语，并观察 request-id、解析地址和重定向链。修复需要出站 allowlist、解析后检查 IPv4/IPv6 和内网地址、逐跳检查重定向、防 DNS rebinding、限制协议端口响应和超时，不能只做字符串黑名单。

---

## 6. CSRF 和 CORS

### 6.1 CSRF

受害者已经登录，浏览器自动带上 Cookie，攻击者诱导浏览器发起状态改变请求。

修复：

- CSRF token；
- 校验 Origin/Referer；
- 合理设置 SameSite；
- 状态改变不用 GET；
- 关键操作重新认证。

### 6.2 CORS

CORS 控制跨源页面能否读取响应。它不能单独替代 CSRF 防护，因为攻击者可能不需要读取响应，只要请求产生副作用。

面试句：

> CORS 主要控制跨源读取，CSRF 防止利用受害者浏览器凭据进行跨站状态改变，两者边界不同。

---

## 7. 文件上传、路径穿越、命令注入

### 7.1 文件上传

不要只检查前端扩展名。服务端要：

- 检查内容、魔数、大小和类型；
- 随机生成文件名；
- 存到 Web 根目录外或对象存储；
- 上传目录禁止脚本执行；
- 下载设置安全 Content-Type；
- 限制压缩包解压路径；
- 文件权限最小化；
- 必要时病毒扫描。

### 7.2 路径穿越

错误：

~~~python
path = "/srv/files/" + user_filename
open(path)
~~~

修复：

1. 规范化路径；
2. 确认结果仍在固定基目录；
3. 更好的是用资源 ID 映射到服务端文件；
4. 限制服务账号权限；
5. 覆盖 Unix/Windows 分隔符、编码和符号链接。

### 7.3 命令注入

错误：

~~~python
os.system("ping " + user_input)
~~~

更安全：

~~~python
subprocess.run(
    ["ping", "-c", "1", validated_host],
    shell=False,
    timeout=3,
    check=False,
)
~~~

还要对 validated_host 做严格校验，使用低权限账号，限制环境变量、工作目录、资源和网络。

---

## 8. 反序列化、XXE、业务逻辑

### 8.1 反序列化

不可信对象在恢复过程中可能触发构造函数、类型逻辑或 gadget 链。

修复：

- 不对不可信数据使用原生对象反序列化；
- 使用带 schema 的数据格式；
- 类型 allowlist；
- 签名和完整性校验；
- 低权限隔离解析；
- 更新漏洞库。

### 8.2 XXE

XML 解析器处理外部实体，可能读取本地文件或发起网络请求。

修复：

- 禁用 DTD；
- 禁用外部实体；
- 禁止外部 schema；
- 使用安全 XML 解析器；
- 限制 XML 大小和嵌套深度。

### 8.3 业务逻辑和竞态

每个接口单独看似安全，但多步骤、并发或状态转换可能绕过规则。

修复：

- 服务端状态机；
- 事务；
- 幂等键；
- 版本号或行锁；
- 重放检测；
- 金额、库存、权限变更做原子检查。

---

## 9. Web 安全和 Agent 的连接

智能渗透 Agent 可以拆成：

~~~text
scope
  ↓
资产/API/JS 发现
  ↓
登录态和角色状态
  ↓
参数与业务流程覆盖
  ↓
漏洞假设
  ↓
工具调用
  ↓
独立验证
  ↓
证据、去重、报告
~~~

每个 turn 至少记录：

~~~text
observation
action
tool_result
policy_decision
evidence
verifier_result
termination
~~~

如果 Agent 已经发出越权请求但没有报告，要逐层检查：

1. 请求是否真的发出；
2. 工具结果是否保存；
3. 是否提取了 A/B 响应差异；
4. verifier 是否判为证据不足；
5. 报告聚合或去重是否丢失。

不要直接说“肯定是 verifier”。

---

## 10. 二面高频回答

### Q：你没有企业开发经验，为什么能做漏洞修复？

> 我过去的优势主要在漏洞发现、复现和根因分析，真实业务防御经验还需要补齐。现在我会按服务端控制来回答修复：参数化查询、对象级授权、上下文编码、出站网络限制和最小权限，并通过代码审查和回归用例验证。这个岗位能让我把攻防经验转化成业务安全工程能力。

### Q：参数化查询能解决所有 SQL 注入吗？

> 不能。它主要处理查询值。动态表名、列名、排序字段要用服务端固定映射或严格白名单；动态 SQL 结构要重新设计，数据库账号也要最小权限。

### Q：为什么 SSRF 不能只用白名单？

> 如果白名单只是域名字符串匹配，仍可能被 DNS rebinding、重定向、IPv6、编码和解析变化绕过。需要解析后检查真实 IP，逐跳检查重定向，并在网络出口层限制目标。

### Q：XSS 的 CSP 能不能代替编码？

> 不能。CSP 是浏览器端辅助控制，不能修复数据进入错误输出上下文的问题。根因修复仍然是安全 API 和正确的上下文编码。

### Q：你当前 verifier 实现到什么程度？

> 当前有 verify 流程，会读取 intent 和执行结果后进行二次审阅，但还不会自动复现所有安全请求，也没有完整持久化独立 verdict。工程化时我会加入结构化证据、差分请求、canary 日志和 confirmed/inconclusive/rejected 状态。

### Q：如何提高漏洞召回率？

> 先固定授权题集、ground truth、账号、预算和 verifier，记录完整轨迹。然后把漏检分成资产发现、认证状态、参数覆盖、假设生成、工具执行、验证器和报告聚合，一次只改一个环节做消融，同时看 recall、precision、重复率、成本和延迟。

---

## 11. 今晚练习顺序

### 第一轮：背代码

1. Python SQL 参数化；
2. Java PreparedStatement；
3. 动态排序字段 allowlist；
4. 对象级授权伪代码；
5. textContent 和 innerHTML；
6. subprocess.run 配合 shell=False。

### 第二轮：每题大声讲五句话

~~~text
入口是什么？
危险点是什么？
证据是什么？
服务端改哪里？
怎么回归？
~~~

### 第三轮：重点模拟

1. 用 Python 写安全查询；
2. 解释动态表名为什么不能直接参数化；
3. 设计两个用户验证 IDOR；
4. 解释 SSRF 的 DNS rebinding 和重定向；
5. 解释 CORS 和 CSRF；
6. 说清当前 verifier 的真实边界；
7. 设计一个 Agent 漏检分类表。

---

## 12. 最后背诵版

> SQL 注入是数据进入 SQL 语法，修复用参数化；动态标识符用固定映射或白名单，数据库最小权限。  
> XSS 是数据进入浏览器代码，按最终输出上下文编码，优先安全 API，CSP 做辅助。  
> IDOR 是认证成功但对象级授权缺失，服务端每次检查用户、租户、角色和资源关系。  
> SSRF 是服务端替用户访问网络，要做出站 allowlist、解析后 IP 检查、IPv4/IPv6、重定向和 DNS rebinding 防护。  
> CSRF 防跨站状态改变，CORS 管跨源读取，两者不能混淆。  
> Agent 评测要固定 ground truth 和预算，按 Discovery、Auth、Coverage、Hypothesis、Tool、Verifier、Report 分桶 FN，再用消融证明改动有效。
