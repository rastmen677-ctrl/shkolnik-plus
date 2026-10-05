require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const { DatabaseSync } = require('node:sqlite');

const {
  ADMIN_LOGIN = 'admin',
  ADMIN_PASSWORD,
  PAYMENT_DETAILS = '',
  PORT = 3000
} = process.env;

const MIN = parseInt(process.env.MIN_DEPOSIT, 10) || 10;

if (!ADMIN_PASSWORD || ADMIN_PASSWORD === 'CHANGE_ME') {
  console.error('Задайте ADMIN_PASSWORD в переменных окружения');
  process.exit(1);
}

let SECRET = process.env.JWT_SECRET;

if (!SECRET || SECRET === 'CHANGE_ME') {
  SECRET = crypto.randomBytes(32).toString('hex');
  console.warn('JWT_SECRET не задан: сессии будут сбрасываться после перезапуска');
}

const app = express();

app.disable('x-powered-by');

if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin'
  });

  next();
});

app.use(express.json({ limit: '20kb' }));
app.use(cookieParser());

const cookieOptions = {
  httpOnly: true,
  sameSite: 'strict',
  secure: process.env.NODE_ENV === 'production'
};

const sign = (data, expiresIn) => {
  return jwt.sign(data, SECRET, { expiresIn });
};

const bad = (res, message, code = 400) => {
  return res.status(code).json({ error: message });
};

/* =========================
   DATABASE
========================= */

const db = new DatabaseSync(
  process.env.DB_FILE || path.join(__dirname, 'data.db')
);

db.exec(`
  PRAGMA journal_mode=WAL;
  PRAGMA foreign_keys=ON;
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    balance INTEGER NOT NULL DEFAULT 0 CHECK(balance>=0),
    blocked INTEGER NOT NULL DEFAULT 0,
    ai_access INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS deposits(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    amount INTEGER NOT NULL CHECK(amount>0),
    transfer_at TEXT,
    payment_comment TEXT,
    proof_file TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    idem_key TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TEXT,
    reviewed_by TEXT,
    rejection_reason TEXT,
    UNIQUE(user_id, idem_key)
  );

  CREATE TABLE IF NOT EXISTS transactions(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    amount INTEGER NOT NULL,
    balance_before INTEGER NOT NULL,
    balance_after INTEGER NOT NULL,
    reference_id TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS admin_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id TEXT NOT NULL,
    action TEXT NOT NULL,
    deposit_id INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS notifications(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS orders(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT,
    subject TEXT,
    budget INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS settings(
    key TEXT PRIMARY KEY,
    value TEXT
  );
`);

try {
  db.exec(
    'ALTER TABLE users ADD COLUMN ai_access INTEGER NOT NULL DEFAULT 0'
  );
} catch {}

try {
  db.exec('ALTER TABLE orders ADD COLUMN service TEXT');
} catch {}

try {
  db.exec('ALTER TABLE orders ADD COLUMN description TEXT');
} catch {}

/* =========================
   TRANSACTIONS
========================= */

let transactionDepth = 0;

const tx = (fn) => (...args) => {
  const level = transactionDepth++;

  db.exec(
    level
      ? `SAVEPOINT s${level}`
      : 'BEGIN IMMEDIATE'
  );

  try {
    const result = fn(...args);

    db.exec(
      level
        ? `RELEASE s${level}`
        : 'COMMIT'
    );

    return result;
  } catch (error) {
    db.exec(
      level
        ? `ROLLBACK TO s${level}; RELEASE s${level}`
        : 'ROLLBACK'
    );

    throw error;
  } finally {
    transactionDepth--;
  }
};

/* =========================
   AUTH
========================= */

const sha = value => {
  return crypto
    .createHash('sha256')
    .update(String(value))
    .digest();
};

const eq = (a, b) => {
  return crypto.timingSafeEqual(
    sha(a),
    sha(b)
  );
};

function user(req, res, next) {
  let currentUser = null;

  try {
    const token = req.cookies.sess;

    if (token) {
      const decoded = jwt.verify(token, SECRET);

      currentUser = db
        .prepare('SELECT * FROM users WHERE id=?')
        .get(decoded.uid);
    }
  } catch {}

  if (!currentUser || currentUser.blocked) {
    return bad(res, 'Требуется вход', 401);
  }

  req.user = currentUser;
  next();
}

function admin(req, res, next) {
  let adminUser = null;

  try {
    const token = req.cookies.adm;

    if (token) {
      adminUser = jwt.verify(token, SECRET).admin;
    }
  } catch {}

  if (!adminUser) {
    return bad(res, 'Требуется вход администратора', 401);
  }

  req.admin = adminUser;
  next();
}

function either(req, res, next) {
  let adminUser = null;

  try {
    const token = req.cookies.adm;

    if (token) {
      adminUser = jwt.verify(token, SECRET).admin;
    }
  } catch {}

  if (adminUser) {
    req.admin = adminUser;
    return next();
  }

  return user(req, res, next);
}

/* =========================
   RATE LIMIT
========================= */

const hits = new Map();

const limit = (max, ms) => {
  return (req, res, next) => {
    const key = req.ip + req.path;
    const now = Date.now();

    const attempts = (hits.get(key) || [])
      .filter(time => now - time < ms);

    if (attempts.length >= max) {
      return bad(
        res,
        'Слишком много попыток, подождите',
        429
      );
    }

    attempts.push(now);
    hits.set(key, attempts);

    next();
  };
};

/* =========================
   HELPERS
========================= */

const AI_PRICE = 3999;

const money = value => {
  return value % 100
    ? (value / 100).toFixed(2)
    : String(value / 100);
};

const notify = (userId, text) => {
  db.prepare(
    'INSERT INTO notifications(user_id,text) VALUES(?,?)'
  ).run(userId, text);
};

const getPaymentDetails = () => {
  const row = db
    .prepare(
      "SELECT value FROM settings WHERE key='payment_details'"
    )
    .get();

  if (row) {
    return row.value;
  }

  if (PAYMENT_DETAILS === 'CHANGE_ME') {
    return '';
  }

  return PAYMENT_DETAILS;
};

/* =========================
   BALANCE
========================= */

const moveBalance = tx(
  (userId, type, amount, reference) => {
    const account = db
      .prepare('SELECT balance FROM users WHERE id=?')
      .get(userId);

    if (!account) {
      throw new Error('USER_NOT_FOUND');
    }

    const newBalance = account.balance + amount;

    if (newBalance < 0) {
      throw new Error('NSF');
    }

    db.prepare(
      'UPDATE users SET balance=? WHERE id=?'
    ).run(newBalance, userId);

    return db.prepare(`
      INSERT INTO transactions(
        user_id,
        type,
        amount,
        balance_before,
        balance_after,
        reference_id
      )
      VALUES(?,?,?,?,?,?)
    `).run(
      userId,
      type,
      amount,
      account.balance,
      newBalance,
      reference
    ).lastInsertRowid;
  }
);

/* =========================
   USERS
========================= */

app.post(
  '/api/register',
  limit(10, 600000),
  (req, res) => {
    const {
      username,
      email,
      password
    } = req.body || {};

    if (
      !/^[\wа-яёіїєґ.-]{3,24}$/i.test(
        username || ''
      )
    ) {
      return bad(
        res,
        'Имя: 3–24 символа'
      );
    }

    if (
      !/^\S+@\S+\.\S+$/.test(
        email || ''
      )
    ) {
      return bad(res, 'Неверный email');
    }

    if (
      typeof password !== 'string' ||
      password.length < 8
    ) {
      return bad(
        res,
        'Пароль — минимум 8 символов'
      );
    }

    try {
      const result = db.prepare(`
        INSERT INTO users(
          username,
          email,
          password_hash
        )
        VALUES(?,?,?)
      `).run(
        username,
        email.toLowerCase(),
        bcrypt.hashSync(password, 10)
      );

      res
        .cookie(
          'sess',
          sign(
            { uid: result.lastInsertRowid },
            '7d'
          ),
          {
            ...cookieOptions,
            maxAge: 7 * 86400000
          }
        )
        .json({ ok: 1 });

    } catch {
      return bad(
        res,
        'Имя или email уже заняты'
      );
    }
  }
);

app.post(
  '/api/login',
  limit(10, 600000),
  (req, res) => {
    const {
      username,
      password
    } = req.body || {};

    const login = String(
      username || ''
    );

    const account = db
      .prepare(
        'SELECT * FROM users WHERE username=? OR email=?'
      )
      .get(
        login,
        login.toLowerCase()
      );

    if (
      !account ||
      account.blocked ||
      !bcrypt.compareSync(
        String(password || ''),
        account.password_hash
      )
    ) {
      return bad(
        res,
        'Неверный логин или пароль',
        401
      );
    }

    res
      .cookie(
        'sess',
        sign(
          { uid: account.id },
          '7d'
        ),
        {
          ...cookieOptions,
          maxAge: 7 * 86400000
        }
      )
      .json({ ok: 1 });
  }
);

app.post(
  '/api/logout',
  (req, res) => {
    res
      .clearCookie('sess', cookieOptions)
      .json({ ok: 1 });
  }
);

app.get(
  '/api/me',
  (req, res) => {
    try {
      const decoded = jwt.verify(
        req.cookies.sess,
        SECRET
      );

      const account = db
        .prepare(
          'SELECT * FROM users WHERE id=?'
        )
        .get(decoded.uid);

      if (account && !account.blocked) {
        return res.json({
          user: account.username,
          balance: account.balance,
          min: MIN,
          ai: !!account.ai_access,
          ai_price: AI_PRICE
        });
      }
    } catch {}

    res.json({
      user: null,
      min: MIN
    });
  }
);

app.get(
  '/api/balance',
  user,
  (req, res) => {
    res.json({
      balance: req.user.balance
    });
  }
);

app.get(
  '/api/transactions',
  user,
  (req, res) => {
    const rows = db.prepare(`
      SELECT
        t.id,
        t.type,
        t.amount,
        t.balance_before,
        t.balance_after,
        t.reference_id,
        t.created_at,
        o.service AS note
      FROM transactions t
      LEFT JOIN orders o
        ON t.reference_id='order:'||o.id
      WHERE t.user_id=?
      ORDER BY t.id DESC
      LIMIT 200
    `).all(req.user.id);

    res.json(rows);
  }
);

app.get(
  '/api/payment-details',
  user,
  (req, res) => {
    res.json({
      details: getPaymentDetails()
    });
  }
);

app.get(
  '/api/notifications',
  user,
  (req, res) => {
    res.json(
      db.prepare(`
        SELECT
          id,
          text,
          read,
          created_at
        FROM notifications
        WHERE user_id=?
        ORDER BY id DESC
        LIMIT 50
      `).all(req.user.id)
    );
  }
);

app.post(
  '/api/notifications/read',
  user,
  (req, res) => {
    db.prepare(
      'UPDATE notifications SET read=1 WHERE user_id=?'
    ).run(req.user.id);

    res.json({ ok: 1 });
  }
);

/* =========================
   AI
========================= */

const aiReply = text => {
  if (/задач|реши|\d/i.test(text)) {
    return `
Давай разберём по шагам:

1) Выпиши, что дано и что нужно найти.
2) Вспомни подходящую формулу или правило.
3) Подставь значения и посчитай.
4) Проверь ответ.

Пришли условие — разберём вместе.
`;
  }

  if (/контрольн|подготов/i.test(text)) {
    return `
План подготовки:

1) Повтори теорию.
2) Реши 5–7 типовых задач.
3) Отметь ошибки.
4) Перерешай сложные задания.

Напиши тему — начнём.
`;
  }

  return `
Объясню простыми словами:

Сначала главная идея,
затем пример,
после этого проверим понимание.

Напиши тему — начнём!
`;
};

app.post(
  '/api/ai/buy',
  user,
  (req, res) => {
    try {
      tx(() => {
        const account = db
          .prepare(
            'SELECT ai_access FROM users WHERE id=?'
          )
          .get(req.user.id);

        if (account.ai_access) {
          throw new Error('HAS');
        }

        moveBalance(
          req.user.id,
          'ai_access',
          -AI_PRICE,
          'ai'
        );

        db.prepare(
          'UPDATE users SET ai_access=1 WHERE id=?'
        ).run(req.user.id);

        notify(
          req.user.id,
          '🟢 AI Помощник подключён!'
        );
      })();

      res.json({ ok: 1 });

    } catch (error) {
      if (error.message === 'NSF') {
        return bad(
          res,
          'Недостаточно средств — пополните баланс',
          402
        );
      }

      if (error.message === 'HAS') {
        return bad(
          res,
          'Доступ уже куплен',
          409
        );
      }

      return bad(
        res,
        'Ошибка',
        500
      );
    }
  }
);

app.post(
  '/api/ai/ask',
  user,
  (req, res) => {
    if (!req.user.ai_access) {
      return bad(
        res,
        'AI Помощник доступен после покупки',
        402
      );
    }

    const question = String(
      req.body?.message || ''
    )
      .trim()
      .slice(0, 2000);

    if (!question) {
      return bad(
        res,
        'Пустой вопрос'
      );
    }

    res.json({
      reply: aiReply(question)
    });
  }
);

/* =========================
   SERVICES
========================= */

const SERVICES = [
  {
    id: 'hw',
    icon: '📝',
    name: 'Помощь с домашним заданием',
    tiers: [
      ['Простое задание', 10],
      ['Среднее задание', 25],
      ['Сложное задание', 50]
    ]
  },
  {
    id: 'task',
    icon: '🧮',
    name: 'Решение задачи',
    tiers: [
      ['Одна простая задача', 10],
      ['Несколько задач', 30],
      ['Сложная / олимпиадная', 60]
    ]
  },
  {
    id: 'explain',
    icon: '📚',
    name: 'Объяснение темы',
    tiers: [
      ['Короткое объяснение', 10],
      ['Подробно, с примерами', 25],
      ['Разбор темы целиком', 50]
    ]
  },
  {
    id: 'pres',
    icon: '📊',
    name: 'Презентация',
    tiers: [
      ['До 5 слайдов', 10],
      ['До 10 слайдов', 30],
      ['До 20 слайдов', 60]
    ]
  },
  {
    id: 'essay',
    icon: '📖',
    name: 'Реферат',
    tiers: [
      ['1–2 страницы', 10],
      ['5–7 страниц', 40],
      ['10+ страниц', 80]
    ]
  },
  {
    id: 'design',
    icon: '🎨',
    name: 'Оформление работы',
    tiers: [
      ['Простое оформление', 10],
      ['Титульный лист и оформление', 20],
      ['Полное оформление', 40]
    ]
  },
  {
    id: 'code',
    icon: '💻',
    name: 'Помощь с программированием',
    tiers: [
      ['Небольшая правка / вопрос', 10],
      ['Задание целиком', 40],
      ['Мини-проект', 90]
    ]
  },
  {
    id: 'project',
    icon: '🔬',
    name: 'Помощь с проектом',
    tiers: [
      ['Консультация', 10],
      ['Часть проекта', 60],
      ['Проект целиком', 120]
    ]
  }
];

app.get(
  '/api/services',
  (req, res) => {
    res.json(SERVICES);
  }
);

/* =========================
   ORDERS
========================= */

app.post(
  '/api/orders',
  user,
  (req, res) => {
    const body = req.body || {};

    const service = SERVICES.find(
      item => item.id === body.service
    );

    const tier = Number(body.tier);

    if (
      !service ||
      !Number.isInteger(tier) ||
      !service.tiers[tier]
    ) {
      return bad(
        res,
        'Выберите услугу и вариант'
      );
    }

    const title = String(
      body.title || ''
    ).trim();

    if (!title) {
      return bad(
        res,
        'Укажите название'
      );
    }

    const price =
      service.tiers[tier][1] * 100;

    try {
      const id = tx(() => {
        const orderId = db.prepare(`
          INSERT INTO orders(
            user_id,
            title,
            subject,
            budget,
            service,
            description
          )
          VALUES(?,?,?,?,?,?)
        `).run(
          req.user.id,
          title.slice(0, 200),
          String(body.subject || '').slice(0, 50),
          price,
          service.name +
            ' — ' +
            service.tiers[tier][0],
          String(
            body.description || ''
          ).slice(0, 3000)
        ).lastInsertRowid;

        moveBalance(
          req.user.id,
          'order_payment',
          -price,
          'order:' + orderId
        );

        return orderId;
      })();

      res.json({
        id,
        price: price / 100
      });

    } catch (error) {
      if (error.message === 'NSF') {
        return bad(
          res,
          'Недостаточно средств — пополните баланс',
          402
        );
      }

      return bad(
        res,
        'Ошибка',
        500
      );
    }
  }
);

/* =========================
   DEPOSITS
========================= */

const UPLOADS = path.join(
  __dirname,
  'uploads'
);

fs.mkdirSync(
  UPLOADS,
  { recursive: true }
);

const EXTENSIONS = {
  'image/png': '.png',
  'image/jpeg': '.jpg',
  'image/webp': '.webp'
};

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOADS,

    filename: (
      req,
      file,
      callback
    ) => {
      callback(
        null,
        crypto.randomBytes(16).toString('hex') +
        EXTENSIONS[file.mimetype]
      );
    }
  }),

  limits: {
    fileSize: 5 * 1024 * 1024,
    files: 1
  },

  fileFilter: (
    req,
    file,
    callback
  ) => {
    if (EXTENSIONS[file.mimetype]) {
      callback(null, true);
    } else {
      callback(
        new Error(
          'Только PNG, JPG или WEBP'
        )
      );
    }
  }
});

const isImage = file => {
  const buffer = Buffer.alloc(12);

  const fd = fs.openSync(
    file.path,
    'r'
  );

  fs.readSync(
    fd,
    buffer,
    0,
    12,
    0
  );

  fs.closeSync(fd);

  return (
    (
      buffer[0] === 0x89 &&
      buffer.toString(
        'latin1',
        1,
        4
      ) === 'PNG'
    ) ||
    (
      buffer[0] === 0xff &&
      buffer[1] === 0xd8 &&
      buffer[2] === 0xff
    ) ||
    (
      buffer.toString(
        'latin1',
        0,
        4
      ) === 'RIFF' &&
      buffer.toString(
        'latin1',
        8,
        12
      ) === 'WEBP'
    )
  );
};

app.post(
  '/api/deposits',
  user,
  limit(15, 600000),
  upload.single('proof'),
  (req, res) => {
    const file = req.file;

    const removeFile = () => {
      if (file) {
        fs.unlink(
          file.path,
          () => {}
        );
      }
    };

    const uah = Number(
      req.body.amount
    );

    const amount = Math.round(
      uah * 100
    );

    const key = String(
      req.body.idem_key || ''
    ).slice(0, 64);

    if (
      file &&
      !isImage(file)
    ) {
      removeFile();

      return bad(
        res,
        'Файл не является изображением'
      );
    }

    if (
      !(uah > 0) ||
      amount < MIN * 100 ||
      amount > 10000000
    ) {
      removeFile();

      return bad(
        res,
        `Минимальная сумма — ${MIN} грн`
      );
    }

    if (!key) {
      removeFile();

      return bad(
        res,
        'Нет ключа запроса'
      );
    }

    const duplicate = db
      .prepare(
        'SELECT id FROM deposits WHERE user_id=? AND idem_key=?'
      )
      .get(
        req.user.id,
        key
      );

    if (duplicate) {
      removeFile();

      return res.json({
        id: duplicate.id,
        duplicate: true
      });
    }

    const pending = db
      .prepare(`
        SELECT COUNT(*) AS count
        FROM deposits
        WHERE user_id=?
        AND status='pending'
      `)
      .get(req.user.id);

    if (pending.count >= 5) {
      removeFile();

      return bad(
        res,
        'Слишком много заявок на проверке'
      );
    }

    const id = tx(() => {
      const depositId = db.prepare(`
        INSERT INTO deposits(
          user_id,
          amount,
          transfer_at,
          payment_comment,
          proof_file,
          idem_key
        )
        VALUES(?,?,?,?,?,?)
      `).run(
        req.user.id,
        amount,
        String(
          req.body.transfer_at || ''
        ).slice(0, 40),
        String(
          req.body.comment || ''
        ).slice(0, 500),
        file ? file.filename : '',
        key
      ).lastInsertRowid;

      notify(
        req.user.id,
        '🟡 Заявка на пополнение отправлена и ожидает проверки.'
      );

      return depositId;
    })();

    res.json({ id });
  }
);

const DEPOSIT_QUERY = `
  SELECT
    d.id,
    d.user_id,
    u.username,
    d.amount,
    d.transfer_at,
    d.payment_comment,
    d.status,
    d.created_at,
    d.reviewed_at,
    d.reviewed_by,
    d.rejection_reason,
    (length(d.proof_file)>0) AS has_proof,
    u.balance AS user_balance
  FROM deposits d
  JOIN users u
    ON u.id=d.user_id
`;

app.get(
  '/api/deposits',
  either,
  (req, res) => {
    const status =
      ['pending', 'approved', 'rejected']
        .includes(req.query.status)
        ? req.query.status
        : null;

    const where = [];
    const args = [];

    if (!req.admin) {
      where.push('d.user_id=?');
      args.push(req.user.id);
    }

    if (status) {
      where.push('d.status=?');
      args.push(status);
    }

    const sql =
      DEPOSIT_QUERY +
      (
        where.length
          ? ' WHERE ' + where.join(' AND ')
          : ''
      ) +
      ' ORDER BY d.id DESC LIMIT 500';

    res.json(
      db.prepare(sql).all(...args)
    );
  }
);

app.get(
  '/api/deposits/:id',
  either,
  (req, res) => {
    const deposit = db
      .prepare(
        DEPOSIT_QUERY +
        ' WHERE d.id=?'
      )
      .get(req.params.id);

    if (
      !deposit ||
      (
        !req.admin &&
        deposit.user_id !== req.user.id
      )
    ) {
      return bad(
        res,
        'Не найдено',
        404
      );
    }

    res.json(deposit);
  }
);

app.get(
  '/api/deposits/:id/proof',
  either,
  (req, res) => {
    const deposit = db
      .prepare(
        'SELECT user_id,proof_file FROM deposits WHERE id=?'
      )
      .get(req.params.id);

    if (
      !deposit ||
      (
        !req.admin &&
        deposit.user_id !== req.user.id
      )
    ) {
      return bad(
        res,
        'Не найдено',
        404
      );
    }

    if (!deposit.proof_file) {
      return bad(
        res,
        'Скриншот не приложен',
        404
      );
    }

    res.set(
      'Cache-Control',
      'private, no-store'
    );

    res.sendFile(
      path.join(
        UPLOADS,
        deposit.proof_file
      )
    );
  }
);

/* =========================
   ADMIN
========================= */

app.post(
  '/api/admin/login',
  limit(5, 600000),
  (req, res) => {
    const {
      login,
      password
    } = req.body || {};

    if (
      !eq(login, ADMIN_LOGIN) ||
      !eq(password, ADMIN_PASSWORD)
    ) {
      return bad(
        res,
        'Неверный логин или пароль',
        401
      );
    }

    db.prepare(`
      INSERT INTO admin_logs(
        admin_id,
        action
      )
      VALUES(?,?)
    `).run(
      ADMIN_LOGIN,
      'login'
    );

    res
      .cookie(
        'adm',
        sign(
          { admin: ADMIN_LOGIN },
          '8h'
        ),
        {
          ...cookieOptions,
          maxAge: 8 * 3600000
        }
      )
      .json({ ok: 1 });
  }
);

app.post(
  '/api/admin/logout',
  (req, res) => {
    res
      .clearCookie(
        'adm',
        cookieOptions
      )
      .json({ ok: 1 });
  }
);

app.get(
  '/api/admin/me',
  admin,
  (req, res) => {
    res.json({
      admin: req.admin
    });
  }
);

const reviewDeposit = (
  req,
  res,
  status
) => {
  const reason = String(
    req.body?.reason || ''
  )
    .trim()
    .slice(0, 300);

  if (
    status === 'rejected' &&
    reason.length < 3
  ) {
    return bad(
      res,
      'Укажите причину отклонения'
    );
  }

  try {
    const result = tx(() => {
      const deposit = db
        .prepare(
          'SELECT * FROM deposits WHERE id=?'
        )
        .get(req.params.id);

      if (!deposit) {
        return {
          error: 'Не найдено',
          code: 404
        };
      }

      const update = db.prepare(`
        UPDATE deposits
        SET
          status=?,
          reviewed_at=CURRENT_TIMESTAMP,
          reviewed_by=?,
          rejection_reason=?
        WHERE id=?
        AND status='pending'
      `).run(
        status,
        req.admin,
        status === 'rejected'
          ? reason
          : null,
        deposit.id
      );

      if (!update.changes) {
        return {
          error: 'Заявка уже обработана',
          code: 409
        };
      }

      if (status === 'approved') {
        moveBalance(
          deposit.user_id,
          'deposit',
          deposit.amount,
          'deposit:' + deposit.id
        );

        notify(
          deposit.user_id,
          `🟢 Ваше пополнение на ${money(deposit.amount)} грн успешно подтверждено.`
        );
      } else {
        notify(
          deposit.user_id,
          `🔴 Заявка на пополнение отклонена. Причина: ${reason}`
        );
      }

      db.prepare(`
        INSERT INTO admin_logs(
          admin_id,
          action,
          deposit_id
        )
        VALUES(?,?,?)
      `).run(
        req.admin,
        status === 'approved'
          ? 'approve'
          : 'reject',
        deposit.id
      );

      return {
        ok: 1
      };
    })();

    if (result.error) {
      return bad(
        res,
        result.error,
        result.code
      );
    }

    res.json(result);

  } catch (error) {
    if (error.message === 'NSF') {
      return bad(
        res,
        'Ошибка баланса',
        500
      );
    }

    return bad(
      res,
      'Ошибка',
      500
    );
  }
};

app.post(
  '/api/admin/deposits/:id/approve',
  admin,
  (req, res) => {
    reviewDeposit(
      req,
      res,
      'approved'
    );
  }
);

app.post(
  '/api/admin/deposits/:id/reject',
  admin,
  (req, res) => {
    reviewDeposit(
      req,
      res,
      'rejected'
    );
  }
);

app.get(
  '/api/admin/transactions',
  admin,
  (req, res) => {
    res.json(
      db.prepare(`
        SELECT
          t.*,
          u.username
        FROM transactions t
        JOIN users u
          ON u.id=t.user_id
        ORDER BY t.id DESC
        LIMIT 500
      `).all()
    );
  }
);

app.get(
  '/api/admin/logs',
  admin,
  (req, res) => {
    res.json(
      db.prepare(`
        SELECT *
        FROM admin_logs
        ORDER BY id DESC
        LIMIT 500
      `).all()
    );
  }
);

app.get(
  '/api/admin/settings',
  admin,
  (req, res) => {
    res.json({
      payment_details:
        getPaymentDetails()
    });
  }
);

app.post(
  '/api/admin/settings',
  admin,
  (req, res) => {
    const details = String(
      req.body?.payment_details || ''
    ).slice(0, 2000);

    db.prepare(`
      INSERT INTO settings(
        key,
        value
      )
      VALUES('payment_details',?)
      ON CONFLICT(key)
      DO UPDATE SET value=excluded.value
    `).run(details);

    db.prepare(`
      INSERT INTO admin_logs(
        admin_id,
        action
      )
      VALUES(?,?)
    `).run(
      req.admin,
      'update_payment_details'
    );

    res.json({
      ok: 1
    });
  }
);

/* =========================
   WEBSITE
========================= */

app.get(
  '/',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'index.html'
      )
    );
  }
);

app.get(
  '/index.html',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'index.html'
      )
    );
  }
);

app.get(
  '/admin.html',
  (req, res) => {
    res.redirect('/admin');
  }
);

app.get(
  '/admin',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'admin.html'
      )
    );
  }
);

/* =========================
   ERROR HANDLER
========================= */

app.use(
  (error, req, res, next) => {
    console.error(error);

    res.status(400).json({
      error:
        error.code === 'LIMIT_FILE_SIZE'
          ? 'Файл больше 5 МБ'
          : error.message || 'Ошибка'
    });
  }
);

/* =========================
   START
========================= */

app.listen(
  PORT,
  () => {
    console.log(
      `Школьник+: http://localhost:${PORT}`
    );
  }
);
