const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');
const path = require('path');
require('dotenv').config();
const REG_CODE = process.env.REG_CODE || '888888'; // 固定验证码（可从 .env 配）
const INGEST_TOKEN = process.env.INGEST_TOKEN || 'dev_ingest_key_123';


const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const {
  DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME, JWT_SECRET
} = process.env;

const pool = mysql.createPool({
  host: DB_HOST || 'localhost',
  port: Number(DB_PORT) || 3306,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
});

async function dbOk() {
  try { await pool.query('SELECT 1'); return true; } catch { return false; }
}

app.get('/health', async (req, res) => {
  res.json({ ok: true, db: await dbOk() ? 'up' : 'down' });
});

/* -------------------- 管理员 注册/登录 -------------------- */
// 说明：为了不改前端，这里同时暴露 /admin/register 与 /register（等价），/admin/login 与 /login（等价）。
async function adminRegisterHandler(req, res) {
  try {
    let { email, password, code } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email 和 password 必填' });
    if (!code) return res.status(400).json({ error: '验证码必填' });

    email = String(email).trim().toLowerCase();

    // ★ 固定验证码校验（后端决定通过与否）
    if (code !== REG_CODE) return res.status(400).json({ error: '验证码不正确' });

    const [exist] = await pool.execute('SELECT 1 FROM admins WHERE email=? LIMIT 1', [email]);
    if (exist.length) return res.status(409).json({ error: '管理员邮箱已存在' });

    const hash = await bcrypt.hash(password, 11);
    const [r] = await pool.execute('INSERT INTO admins (email, password_hash) VALUES (?, ?)', [email, hash]);
    res.status(201).json({ id: r.insertId, role: 'admin' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: '服务器错误' });
  }
}


async function adminLoginHandler(req, res) {
  try {
    let { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email 和 password 必填' });
    email = String(email).trim().toLowerCase();

    const [rows] = await pool.execute('SELECT * FROM admins WHERE email=? LIMIT 1', [email]);
    if (!rows.length) return res.status(401).json({ error: '邮箱或密码错误' });
    const admin = rows[0];

    const ok = await bcrypt.compare(password, admin.password_hash);
    if (!ok) return res.status(401).json({ error: '邮箱或密码错误' });

    const token = jwt.sign({ id: admin.id, role: 'admin' }, JWT_SECRET || 'dev_secret_change_me', { expiresIn: '2h' });
    res.json({ token, role: 'admin' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: '服务器错误' });
  }
}

app.post('/admin/register', adminRegisterHandler);
app.post('/register',       adminRegisterHandler); // 与前端保持兼容

app.post('/admin/login',    adminLoginHandler);
app.post('/login',          adminLoginHandler);    // 与前端保持兼容

/* -------------------- 管理员鉴权 -------------------- */
function adminAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7).trim() : null;
  if (!token) return res.sendStatus(401);
  try {
    const payload = jwt.verify(token, JWT_SECRET || 'dev_secret_change_me');
    if (payload.role !== 'admin') return res.sendStatus(403);
    req.adminId = payload.id;
    next();
  } catch {
    return res.sendStatus(403);
  }
}

/* -------------------- 数据查询（只有管理员能看） -------------------- */
// 1) 用户列表（支持按 email 模糊搜索；返回 id/email/name/region）
app.get('/users', adminAuth, async (req, res) => {
  const q = String(req.query.email || '').trim().toLowerCase();
  let sql = 'SELECT id, email, name, region FROM users';
  const params = [];
  if (q) { sql += ' WHERE LOWER(email) LIKE ?'; params.push(`%${q}%`); }
  sql += ' ORDER BY id ASC';
  const [rows] = await pool.execute(sql, params);
  res.json(rows);
});

// 2) 行为日志（可按 email 或 user_id 过滤；Join 出用户信息）
app.get('/logs', adminAuth, async (req, res) => {
  const email = String(req.query.email || '').trim().toLowerCase();
  const userId = req.query.user_id ? Number(req.query.user_id) : null;

  let base =
    `SELECT l.id, l.user_id AS userId, u.email, u.name, u.region, l.action, l.at
     FROM logs l
     LEFT JOIN users u ON u.id = l.user_id`;
  const where = [];
  const params = [];
  if (email) { where.push('LOWER(u.email) LIKE ?'); params.push(`%${email}%`); }
  if (userId) { where.push('l.user_id = ?'); params.push(userId); }
  if (where.length) base += ' WHERE ' + where.join(' AND ');
  base += ' ORDER BY l.id ASC';

  const [rows] = await pool.execute(base, params);
  res.json(rows);
});

/* 可选：便于演示/测试，管理员可手动写入一条行为日志
   POST /logs { user_id, action }  */
app.post('/logs', adminAuth, async (req, res) => {
  const { user_id, action } = req.body || {};
  if (!user_id || !action) return res.status(400).json({ error: 'user_id 与 action 必填' });
  await pool.execute('INSERT INTO logs (user_id, action, at) VALUES (?, ?, NOW())', [user_id, action]);
  res.status(201).json({ ok: true });
});

const PORT = process.env.PORT || 3000;
// 关键词统计（管理员）
// GET /llm/keywords?keywords=draw,make%20a%20pdf,resume&session=sess-001
// 规则：按给定顺序做“第一个命中”的归类；其余归 other，保证总和=100%
// 关键词统计（管理员）——支持 email 或 session 过滤
// ========== 关键词汇总 ==========
app.get('/llm/keywords', adminAuth, async (req, res) => {
  try {
    const raw = String(req.query.keywords || 'draw,make a pdf,resume');
    const keywords = raw.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    const sessionKey = String(req.query.session || '').trim();
    const email = String(req.query.email || '').trim().toLowerCase();

    // 时间参数（字符串；可能是 YYYY-MM-DD 或 YYYY-MM-DD HH:MM:SS）
    const fromStr = String(req.query.from || '').trim();
    const toStr   = String(req.query.to   || '').trim();
    const isDateOnly = s => /^\d{4}-\d{2}-\d{2}$/.test(s);

    // 1) 统计总数
    let totalSql = `
      SELECT COUNT(*) AS total
      FROM llm_events e
      LEFT JOIN llm_sessions s ON s.id = e.session_id
      LEFT JOIN users u ON u.id = e.user_id
      WHERE e.event_type = 'prompt'
    `;
    const totalParams = [];
    if (sessionKey) { totalSql += ' AND s.session_key = ?'; totalParams.push(sessionKey); }
    if (email)      { totalSql += ' AND LOWER(u.email) = ?'; totalParams.push(email); }
    if (fromStr)    { totalSql += ' AND e.ts >= ?';        totalParams.push(isDateOnly(fromStr) ? `${fromStr} 00:00:00` : fromStr); }
    if (toStr) {
      if (isDateOnly(toStr)) { totalSql += ' AND e.ts < DATE_ADD(?, INTERVAL 1 DAY)'; totalParams.push(toStr); }
      else                   { totalSql += ' AND e.ts <= ?';                           totalParams.push(toStr); }
    }
    const [tot] = await pool.execute(totalSql, totalParams);
    const total = Number(tot[0]?.total || 0);
    if (total === 0) {
      return res.json({ total: 0, buckets: keywords.map(k => ({ name: k, count: 0 })), other: 0 });
    }

    // 2) 分桶：命中“第一个关键词”，否则 other
    const pcol = "LOWER(COALESCE(e.prompt,''))";
    let caseExpr = 'CASE';
    const params = [];
    for (const k of keywords) { caseExpr += ` WHEN ${pcol} LIKE ? THEN ?`; params.push(`%${k}%`, k); }
    caseExpr += " ELSE 'other' END AS bucket";

    let sql = `
      SELECT bucket, COUNT(*) AS cnt
      FROM (
        SELECT ${caseExpr}
        FROM llm_events e
        LEFT JOIN llm_sessions s ON s.id = e.session_id
        LEFT JOIN users u ON u.id = e.user_id
        WHERE e.event_type='prompt'
        ${sessionKey ? 'AND s.session_key=?' : ''}
        ${email      ? 'AND LOWER(u.email)=?' : ''}
        ${fromStr    ? 'AND e.ts >= ?'        : ''}
        ${toStr
          ? (isDateOnly(toStr) ? 'AND e.ts < DATE_ADD(?, INTERVAL 1 DAY)' : 'AND e.ts <= ?')
          : ''}
      ) t
      GROUP BY bucket
    `;
    if (sessionKey) params.push(sessionKey);
    if (email)      params.push(email);
    if (fromStr)    params.push(isDateOnly(fromStr) ? `${fromStr} 00:00:00` : fromStr);
    if (toStr) {
      if (isDateOnly(toStr)) params.push(toStr);
      else                   params.push(toStr);
    }

    const [rows] = await pool.execute(sql, params);
    const map = Object.fromEntries(rows.map(r => [r.bucket, Number(r.cnt)]));
    const buckets = keywords.map(k => ({ name: k, count: map[k] || 0 }));
    const matched = buckets.reduce((s, b) => s + b.count, 0);
    const other = Math.max(0, total - matched);
    res.json({ total, buckets, other });
  } catch (e) {
    console.error('keywords error:', e);
    res.status(500).json({ error: 'server error' });
  }
});

// ========== 关键词示例 ==========
app.get('/llm/keywords/examples', adminAuth, async (req, res) => {
  try {
    const raw = String(req.query.keywords || 'draw,make a pdf,resume');
    const keywords = raw.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    let target = String(req.query.keyword || '').trim().toLowerCase();
    if (!target) target = keywords[0] || 'other';

    const sessionKey = String(req.query.session || '').trim();
    const email = String(req.query.email || '').trim().toLowerCase();
    const limit = Math.min(parseInt(req.query.limit || '20', 10) || 20, 100);

    const fromStr = String(req.query.from || '').trim();
    const toStr   = String(req.query.to   || '').trim();
    const isDateOnly = s => /^\d{4}-\d{2}-\d{2}$/.test(s);

    const pcol = "LOWER(COALESCE(e.prompt,''))";
    let sql = `
      SELECT e.id, e.ts, s.session_key AS sessionKey, u.email, e.prompt
      FROM llm_events e
      LEFT JOIN llm_sessions s ON s.id = e.session_id
      LEFT JOIN users u        ON u.id = e.user_id
      WHERE e.event_type='prompt'
    `;
    const params = [];
    if (sessionKey) { sql += ' AND s.session_key = ?'; params.push(sessionKey); }
    if (email)      { sql += ' AND LOWER(u.email) = ?'; params.push(email); }
    if (fromStr)    { sql += ' AND e.ts >= ?';         params.push(isDateOnly(fromStr) ? `${fromStr} 00:00:00` : fromStr); }
    if (toStr) {
      if (isDateOnly(toStr)) { sql += ' AND e.ts < DATE_ADD(?, INTERVAL 1 DAY)'; params.push(toStr); }
      else                   { sql += ' AND e.ts <= ?';                            params.push(toStr); }
    }

    if (target === 'other') {
      if (keywords.length) {
        sql += ' AND ' + keywords.map(() => `${pcol} NOT LIKE ?`).join(' AND ');
        for (const k of keywords) params.push(`%${k}%`);
      }
    } else {
      const idx = keywords.indexOf(target);
      sql += ` AND ${pcol} LIKE ?`; params.push(`%${target}%`);
      for (let i = 0; i < idx; i++) { sql += ` AND ${pcol} NOT LIKE ?`; params.push(`%${keywords[i]}%`); }
    }

    sql += ' ORDER BY e.ts DESC LIMIT ' + limit;
    const [rows] = await pool.query(sql, params);

    res.json({
      keyword: target,
      examples: rows.map(r => ({ id: r.id, ts: r.ts, sessionKey: r.sessionKey, email: r.email, prompt: r.prompt }))
    });
  } catch (e) {
    console.error('examples error:', e);
    res.status(500).json({ error: 'server error' });
  }
});

// ====== Intent 规则：命中即判为该意图（按顺序优先）======
const INTENT_RULES = [
  { name: '绘图/生成图片',   patterns: [/draw|image|picture|diagram|sketch|画|生成图片|出图/i] },
  { name: '生成PDF/文档',   patterns: [/pdf|make\s+a\s+pdf|导出\s*pdf|生成(文档|报告)/i] },
  { name: '简历/求职材料', patterns: [/resume|cv|cover\s*letter|简历|求职|职位|投递/i] },
  { name: '写作/改写润色', patterns: [/write|rewrite|summary|email|article|报告|写一篇|改写|润色/i] },
  { name: '翻译',         patterns: [/translate|translation|翻译|英译中|中译英/i] },
  { name: '代码/编程',     patterns: [/code|bug|python|java|js|函数|脚本|报错|调试|编程/i] },
  { name: '数据分析/可视化', patterns: [/chart|plot|csv|excel|统计|分析|可视化|图表|可视化/i] },
  { name: '问答/搜索',     patterns: [/who|what|why|where|how|查找|查询|搜索|问题|问答/i] },
];

function classifyIntent(text) {
  const t = (text || '').toString();
  for (const r of INTENT_RULES) {
    if (r.patterns.some(p => p.test(t))) return r.name;
  }
  return 'other';
}

// 同时参考 prompt + response（响应权重更高一点可选）
function classifyPair(prompt, response) {
  const both = `${prompt || ''}\n${response || ''}`;
  return classifyIntent(both);
}


// ====== GET /llm/intents  按意图聚合（可按 email / session / from / to 过滤）======
app.get('/llm/intents', adminAuth, async (req, res) => {
  const email = String(req.query.email || '').trim().toLowerCase();
  const sessionKey = String(req.query.session || '').trim();
  const from = req.query.from ? new Date(req.query.from) : null;
  const to   = req.query.to   ? new Date(req.query.to)   : null;
  const limit = Math.min(parseInt(req.query.limit || '8000', 10), 30000);

  let sql = `
    SELECT e.event_type, e.ts, e.prompt, e.response,
           s.session_key AS sessionKey, u.email
    FROM llm_events e
    LEFT JOIN llm_sessions s ON s.id = e.session_id
    LEFT JOIN users u        ON u.id = e.user_id
    WHERE e.event_type IN ('prompt','response')
  `;
  const params = [];
  if (email)      { sql += ' AND LOWER(u.email) LIKE ?'; params.push(`%${email}%`); }
  if (sessionKey) { sql += ' AND s.session_key = ?';     params.push(sessionKey); }
  if (from)       { sql += ' AND e.ts >= ?';             params.push(from); }
  if (to)         { sql += ' AND e.ts <= ?';             params.push(to); }
  sql += ' ORDER BY e.ts DESC LIMIT ' + limit;

  const [rows] = await pool.execute(sql, params);
  const turns = buildTurns(rows, 120);

  // 全局聚合
  const buckets = new Map();
  const perSession = new Map();
  for (const t of turns) {
    const intent = classifyPair(t.prompt, t.response);
    buckets.set(intent, (buckets.get(intent) || 0) + 1);

    if (!perSession.has(t.sessionKey)) perSession.set(t.sessionKey, []);
    perSession.get(t.sessionKey).push(t);
  }

  // 每会话“总意图”
  const sessionIntents = [];
  for (const [sess, arr] of perSession.entries()) {
    const s = summarizeSessionIntent(arr);
    sessionIntents.push({ sessionKey: sess, total: s.total, topIntent: s.topIntent, support: s.support, confidence: s.confidence });
  }
  sessionIntents.sort((a,b) => b.confidence - a.confidence);

  // 输出 buckets
  const outBuckets = [];
  for (const r of INTENT_RULES.concat({ name:'other' })) {
    outBuckets.push({ name: r.name, count: buckets.get(r.name) || 0 });
  }

  res.json({
    total: turns.length,
    buckets: outBuckets,
    sessionIntents
  });
});

// ====== 拉某意图的示例（配对后分类）======
app.get('/llm/intents/examples', adminAuth, async (req, res) => {
  const email = String(req.query.email || '').trim().toLowerCase();
  const sessionKey = String(req.query.session || '').trim();
  const intent = String(req.query.intent || 'other').trim();
  const from = req.query.from ? new Date(req.query.from) : null;
  const to   = req.query.to   ? new Date(req.query.to)   : null;
  const limit = Math.min(parseInt(req.query.limit || '20', 10), 200);

  let sql = `
    SELECT e.event_type, e.ts, e.prompt, e.response,
           s.session_key AS sessionKey, u.email
    FROM llm_events e
    LEFT JOIN llm_sessions s ON s.id = e.session_id
    LEFT JOIN users u        ON u.id = e.user_id
    WHERE e.event_type IN ('prompt','response')
  `;
  const params = [];
  if (email)      { sql += ' AND LOWER(u.email) LIKE ?'; params.push(`%${email}%`); }
  if (sessionKey) { sql += ' AND s.session_key = ?';     params.push(sessionKey); }
  if (from)       { sql += ' AND e.ts >= ?';             params.push(from); }
  if (to)         { sql += ' AND e.ts <= ?';             params.push(to); }
  sql += ' ORDER BY e.ts DESC LIMIT 4000';

  const [rows] = await pool.execute(sql, params);
  const turns = buildTurns(rows, 120);

  const examples = [];
  for (const t of turns) {
    if (classifyPair(t.prompt, t.response) === intent) {
      examples.push({
        ts: t.ts,
        sessionKey: t.sessionKey,
        prompt: t.prompt || '',
        response: t.response || ''
      });
      if (examples.length >= limit) break;
    }
  }
  res.json({ intent, examples });
});



app.listen(PORT, () => console.log(`Server on http://localhost:${PORT}`));
// === LLM 事件：确保会话存在 ===
async function ensureSession(sessionKey, userId = null, meta = null) {
  const [rows] = await pool.execute('SELECT id FROM llm_sessions WHERE session_key=? LIMIT 1', [sessionKey]);
  if (rows.length) return rows[0].id;
  const [r] = await pool.execute(
    'INSERT INTO llm_sessions (session_key, user_id, meta) VALUES (?,?,?)',
    [sessionKey, userId, meta ? JSON.stringify(meta) : null]
  );
  return r.insertId;
}

// 按 sessionKey 将 prompt/response 排序，并尽量“配对”成轮次：prompt → 最近的 response
function buildTurns(rows, maxGapSec = 120) {
  const bySess = new Map();
  for (const r of rows) {
    const key = r.sessionKey || 'unknown';
    if (!bySess.has(key)) bySess.set(key, []);
    bySess.get(key).push(r);
  }
  for (const arr of bySess.values()) arr.sort((a,b)=> new Date(a.ts) - new Date(b.ts));

  const turns = [];
  for (const [sess, arr] of bySess.entries()) {
    let pending = null;
    for (const r of arr) {
      if (r.event_type === 'prompt') {
        // 如果已有未配对 prompt，先把它单独成一个轮次
        if (pending) { turns.push({ sessionKey: sess, prompt: pending.prompt, ts: pending.ts }); }
        pending = { prompt: r.prompt, ts: r.ts };
      } else if (r.event_type === 'response') {
        if (pending) {
          const dt = (new Date(r.ts) - new Date(pending.ts)) / 1000;
          if (dt <= maxGapSec) {
            turns.push({ sessionKey: sess, prompt: pending.prompt, response: r.response, ts: r.ts });
            pending = null;
            continue;
          } else {
            // 过久：先结算旧 prompt 再单独结算 response
            turns.push({ sessionKey: sess, prompt: pending.prompt, ts: pending.ts });
            pending = null;
          }
        }
        // 单独的 response
        turns.push({ sessionKey: sess, response: r.response, ts: r.ts });
      }
    }
    if (pending) turns.push({ sessionKey: sess, prompt: pending.prompt, ts: pending.ts });
  }
  return turns;
}

// 计算会话的“总意图”
function summarizeSessionIntent(turnsOfOneSession) {
  const counts = new Map();
  let total = 0;
  for (const t of turnsOfOneSession) {
    const intent = classifyPair(t.prompt, t.response);
    counts.set(intent, (counts.get(intent) || 0) + 1);
    total++;
  }
  if (total === 0) return { topIntent: null, confidence: 0, support: 0, total: 0 };

  // 选出现次数最多的意图；若并列，按 INTENT_RULES 的定义顺序决定优先级
  let top = { name: 'other', count: -1 };
  for (const r of INTENT_RULES.concat({name:'other'})) {
    const c = counts.get(r.name) || 0;
    if (c > top.count) top = { name: r.name, count: c };
  }
  return { topIntent: top.name, confidence: Number((top.count/total).toFixed(3)), support: top.count, total };
}

// 计算并写回 llm_sessions.final_* 字段
async function computeAndPersistSessionIntentById(sessionId) {
  const [rows] = await pool.execute(`
    SELECT e.event_type, e.ts, e.prompt, e.response,
           s.session_key AS sessionKey
    FROM llm_events e
    LEFT JOIN llm_sessions s ON s.id = e.session_id
    WHERE e.session_id = ?
      AND e.event_type IN ('prompt','response')
    ORDER BY e.ts ASC
  `, [sessionId]);

  const turns = buildTurns(rows);
  const summary = summarizeSessionIntent(turns);
  await pool.execute(
    `UPDATE llm_sessions
     SET final_intent=?, final_confidence=?, final_at=NOW()
     WHERE id=?`,
    [summary.topIntent, summary.confidence, sessionId]
  );
  return summary;
}

// === LLM 行为上报（用 x-ingest-key 校验；无需登录态） ===
app.post('/llm/track', async (req, res) => {
  try {
    const key = req.headers['x-ingest-key'];
    if (!key || key !== INGEST_TOKEN) return res.sendStatus(401);

    let {
      sessionId, userEmail, userId,
      eventType,                 // 'prompt' | 'response' | 'tool_call' | 'tool_result' | 'error' | ... | 'session_end'
      role,                      // 'user' | 'assistant' | 'system' | 'tool'
      channel,                   // 'chat' | 'tool' | 'embed' | 'rerank' ...
      prompt, response,          // 文本（按事件任选其一）
      tool,                      // { name, args }
      error, errorCode,          // 错误文本 + 错误码
      tags,                      // 任意JSON标签
      meta                       // 附加字段
    } = req.body || {};

    if (!sessionId || !eventType) return res.status(400).json({ error: 'sessionId 与 eventType 必填' });

    if (!userId && userEmail) {
      const [u] = await pool.execute('SELECT id FROM users WHERE email=? LIMIT 1', [String(userEmail).toLowerCase()]);
      userId = u.length ? u[0].id : null;
    }

    const sid = await ensureSession(String(sessionId), userId, meta);
    const toolName = tool?.name || null;
    const toolArgs = tool?.args ? JSON.stringify(tool.args) : null;
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().slice(0,45);
    const ua = (req.headers['user-agent'] || '').toString().slice(0,255);

    // —— 写入事件
    await pool.execute(
      `INSERT INTO llm_events
       (session_id, user_id, event_type, role, channel,
        prompt, response, tool_name, tool_args,
        error, error_code,
        ip, user_agent, tags, meta)
       VALUES (?,?,?,?,?,
               ?,?,?,?,?,?,
               ?,?,?,?)`,
      [
        sid, userId || null, String(eventType), role || null, channel || null,
        prompt || null, response || null, toolName, toolArgs,
        error || null, errorCode || null,
        ip, ua, tags ? JSON.stringify(tags) : null, meta ? JSON.stringify(meta) : null
      ]
    );

    // ——【新增1】更新会话起止时间
    await pool.execute(
      `UPDATE llm_sessions
         SET started_at = COALESCE(started_at, NOW()),
             ended_at   = NOW()
       WHERE id=?`,
      [sid]
    );

    // ——【新增2】若为“结束会话”事件，计算并写回总意图
    const endEvents = new Set(['session_end', 'end', 'logout', 'conversation_end']);
    if (endEvents.has(String(eventType))) {
      try {
        await computeAndPersistSessionIntentById(sid);
      } catch (e) {
        console.error('finalize intent error:', e);
      }
    }

    res.status(201).json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: '服务器错误' });
  }
});


// === 管理员查询：会话列表 ===
app.get('/llm/sessions', adminAuth, async (req, res) => {
  const email = String(req.query.email || '').trim().toLowerCase();
  let sql = `SELECT s.id, s.session_key AS sessionKey, s.user_id AS userId, u.email,
                    s.started_at, s.ended_at, s.final_intent AS finalIntent, s.final_confidence AS finalConfidence
             FROM llm_sessions s LEFT JOIN users u ON u.id = s.user_id`;
  const params = [];
  if (email) { sql += ' WHERE LOWER(u.email) LIKE ?'; params.push(`%${email}%`); }
  sql += ' ORDER BY s.started_at DESC LIMIT 200';
  const [rows] = await pool.execute(sql, params);
  res.json(rows);
});


// 手动结算会话总意图：POST /llm/sessions/finalize { session: "xxx" }
app.post('/llm/sessions/finalize', adminAuth, async (req, res) => {
  const { session } = req.body || {};
  if (!session) return res.status(400).json({ error: 'session 必填' });
  const [r] = await pool.execute('SELECT id FROM llm_sessions WHERE session_key=? LIMIT 1', [session]);
  if (!r.length) return res.status(404).json({ error: 'session 不存在' });
  const summary = await computeAndPersistSessionIntentById(r[0].id);
  res.json({ ok: true, session, ...summary });
});


// === 管理员查询：事件列表 ===
app.get('/llm/events', adminAuth, async (req, res) => {
  const email = String(req.query.email || '').trim().toLowerCase();
  const sessionKey = String(req.query.session || '').trim();
  const type = String(req.query.type || '').trim();
  const from = req.query.from ? new Date(req.query.from) : null;
  const to   = req.query.to   ? new Date(req.query.to)   : null;
  const limit = Math.min(parseInt(req.query.limit || '200', 10), 1000);

  let base = `
    SELECT e.id, e.ts, e.event_type AS type, e.role, e.channel,
          e.prompt, e.response, e.tool_name,
          e.error, e.error_code,
          u.email, s.session_key AS sessionKey
    FROM llm_events e
      LEFT JOIN users u ON u.id = e.user_id
      LEFT JOIN llm_sessions s ON s.id = e.session_id
  `;

  const where = [];
  const params = [];
  if (email)      { where.push('LOWER(u.email) LIKE ?'); params.push(`%${email}%`); }
  if (sessionKey) { where.push('s.session_key = ?');     params.push(sessionKey); }
  if (type)       { where.push('e.event_type = ?');      params.push(type); }
  if (from)       { where.push('e.ts >= ?');             params.push(from); }
  if (to)         { where.push('e.ts <= ?');             params.push(to); }
  if (where.length) base += ' WHERE ' + where.join(' AND ');
  base += ' ORDER BY e.ts DESC LIMIT ' + limit;

  const [rows] = await pool.execute(base, params);
  res.json(rows);
});

