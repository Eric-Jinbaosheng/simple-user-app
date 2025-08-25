Simple User App (Node + MySQL)

一个简洁的管理员后台 + 数据采集与可视化项目：

管理员注册 / 登录（JWT）

用户列表（id / email / name / region）与行为日志

接收你们自有 LLM 的行为上报

关键词统计可视化（饼图 + 时间/会话筛选 + 关键词预设 + 导出 CSV/PNG）

（可选）意图统计接口与示例

前端页面

/：主页（登录、用户/日志列表、进入可视化）

/viz.html：关键词可视化页面

目录结构
.
├─ public/                 # 前端静态文件（index.html, viz.html）
├─ server.js               # 后端（Express）
├─ schema.sql              # 建库建表脚本
├─ seed.sql                # 演示数据（可选）
├─ .env.example            # 环境变量示例（复制为 .env）
├─ .gitignore
├─ package.json
└─ README.md

环境要求

Node.js >= 18

MySQL 8.x

快速开始
1) 安装依赖
npm install

2) 初始化数据库

登录 MySQL 后执行：

SOURCE schema.sql;
-- 可选：插入演示数据
SOURCE seed.sql;

3) 配置环境变量

将 .env.example 复制为 .env 并按实际修改：

# MySQL
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=simple_user_app

# Auth
JWT_SECRET=please_change_me    # 用足够随机的字符串

# 管理员注册用的固定验证码
REG_CODE=888888

# /llm/track 上报接口鉴权
INGEST_TOKEN=dev_ingest_key_123

# Server
PORT=3000


⚠️ .env 请勿提交到仓库。.gitignore 已默认忽略。

4) 本地运行

开发模式（需要 nodemon）：

npm run dev


或生产/普通模式：

npm start


访问：http://localhost:3000

Windows 提示：若遇到 “npm.ps1 因执行策略被禁止”，在 PowerShell 执行：

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

使用说明
管理员注册 / 登录

打开首页 /

注册：输入邮箱/密码 + 验证码（默认为 REG_CODE），成功后返回登录页

登录：获取到 token 后即可访问受保护接口

用户与日志

登录后可在主页按 email 搜索用户、查看用户行为日志

日志也可按 email 过滤

关键词可视化

首页输入某个用户的邮箱，点击 “可视化” 进入 /viz.html?email=<user>

支持：

关键词（逗号分隔）

会话筛选（下拉）

起止日期（from / to）

关键词预设：保存/更新/删除/切换（保存在浏览器 localStorage，按邮箱隔离）

导出 CSV / 下载 PNG

点击饼图扇区可查看该分类下的 示例 prompts

上报 LLM 行为

端点

POST /llm/track
Headers: x-ingest-key: <INGEST_TOKEN>
Content-Type: application/json


Body(JSON)

{
  "sessionId": "sess-001",
  "userEmail": "alice@example.com",   // 或 userId（二选一）
  "eventType": "prompt",              // prompt | response | tool_call | tool_result | error | session_end
  "role": "user",                     // user | assistant | system | tool
  "channel": "chat",
  "prompt": "draw a cat in ascii",
  "response": "（可选）",
  "tool": { "name": "search", "args": {"q":"..."} },
  "error": null,
  "errorCode": null,
  "tags": { "lang": "en" },           // 任意 JSON
  "meta": { "app": "web" }            // 任意 JSON
}


说明

系统会自动 ensure session（会话不存在则创建）

若 userId 未给、但传了 userEmail，系统会去 users.email 匹配 id

eventType = "session_end" 可用于结算会话（后端会将该会话的最终意图写入 llm_sessions.final_intent / final_confidence / final_at）

简易示例（curl）

curl -X POST http://localhost:3000/llm/track \
  -H "Content-Type: application/json" \
  -H "x-ingest-key: dev_ingest_key_123" \
  -d '{
    "sessionId":"sess-001",
    "userEmail":"alice@example.com",
    "eventType":"prompt",
    "role":"user",
    "prompt":"make a pdf from these notes..."
  }'

管理接口（节选）

以下接口均需 Authorization: Bearer <token>（管理员登录获取）

GET /users?email=<q>
列出用户（可模糊搜索 email）

GET /logs?email=<q>&user_id=<id>
列出行为日志（支持 email 或 user_id 过滤）

POST /logs
手工写入一条日志（演示用途）

GET /llm/sessions?email=<user@x.com>
列出该用户的会话（含 final_intent / final_confidence / final_at）

GET /llm/events?email=&session=&type=&from=&to=&limit=
查询事件列表（按用户/会话/时间范围筛选）

GET /llm/keywords?keywords=a,b,c&email=&session=&from=&to=
统计关键词命中（按第一个命中关键词归类），返回：

{ "total": 42, "buckets": [ { "name":"draw", "count":10 }, ... ], "other": 5 }


GET /llm/keywords/examples?keyword=<k>&keywords=a,b,c&email=&session=&from=&to=&limit=20
返回该分类下的示例 prompts（时间倒序）

（可选）GET /llm/intents?email=&session=&from=&to=
统计意图分布（基于 prompt+response 的启发式规则）

（可选）GET /llm/intents/examples?intent=<name>&...
某意图的示例

生产环境注意事项

Secrets：务必更换 JWT_SECRET / REG_CODE / INGEST_TOKEN 并妥善保存

CORS：默认 cors() 全开，公网部署时建议按域名收紧

数据库权限：为应用单独创建 MySQL 用户并最小化权限

日志：根据需要接入持久化日志（如 PM2 / Docker / 反向代理访问日志）

许可

本项目建议使用 MIT License（在仓库根目录放置 LICENSE 文件）。

常见问题

浏览器打不开 http://localhost:3000：确认服务已启动、端口未占用、防火墙未拦截。

Windows 提示 npm.ps1 禁止执行：PowerShell 执行

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass


接口 401/403：确认已登录并把 token 放到 Authorization: Bearer <token>，或 x-ingest-key 是否正确。
