const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
require('dotenv').config(); 
const db = require('./db');
const { requireAuth } = require('./middleware');

const app = express();
app.locals.db = db;

app.use(cors());
app.use(express.json());

// basic security headers for backend responses
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', "default-src 'none'; connect-src 'self'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    next();
});

// explicit handler to avoid noisy .well-known request errors in devtools/extensions
app.get('/.well-known/appspecific/com.chrome.devtools.json', (req, res) => {
    res.status(204).end();
});

app.get('/', (req, res) => {
    res.status(200).json({ status: 'ok', message: 'Server is running' });
});

const JWT_SECRET = process.env.JWT_SECRET || 'my_secret_key_123';
const baseUrl = process.env.FRONTEND_URL || 'http://localhost:5173';

// note: Настройка nodemailer для отправки email
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { 
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS 
    }
});

/**
 * POST /api/register
 * important: Регистрация нового пользователя
 * note: Пароль хешируется перед сохранением
 * nota bene: Уникальный индекс в БД гарантирует уникальность email
 */
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    
    // important: Валидация полей
    if (!name || !email || !password) {
        return res.status(400).json({ error: 'Все поля обязательны' });
    }

    // note: Хеширование пароля
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const [result] = await db.execute(
            'INSERT INTO users (name, email, password, status) VALUES (?, ?, ?, ?)',
            [name, email, hashedPassword, 'unverified']
        );
        
        // note: Формирование ссылки для подтверждения
        const verifyUrl = `${baseUrl}/verify-email?id=${result.insertId}`;
        
        // note: Асинхронная отправка email (не блокирует ответ)
        if (process.env.EMAIL_USER) {
            transporter.sendMail({
                to: email,
                subject: 'Подтвердите ваш email',
                text: `Нажмите здесь для подтверждения: ${verifyUrl}`
            }).catch(err => console.error('[EMAIL ERROR]', err));
        } else {
            console.log(`[MOCK EMAIL] Кому: ${email}. Ссылка: ${verifyUrl}`);
        }

        // note: Пользователь зарегистрирован сразу
        res.status(201).json({ message: 'Пользователь успешно зарегистрирован.' });
    } catch (err) {
        // important: Обработка дубликата email (уникальный индекс)
        if (err.code === 'ER_DUP_ENTRY') { 
            return res.status(400).json({ error: 'Email уже существует.' });
        }
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

/**
 * POST /api/login
 * note: Аутентификация пользователя
 * important: Блокированные пользователи не могут войти
 */
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        const user = rows[0];

        if (!user) return res.status(400).json({ error: 'Неверные учетные данные' });

        // important: Проверка статуса перед входом
        if (user.status === 'blocked') {
            return res.status(403).json({ error: 'Аккаунт заблокирован.' });
        }

        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) return res.status(400).json({ error: 'Неверные учетные данные' });

        // note: Обновление времени последнего входа
        await db.execute('UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);

        const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, name: user.name, status: user.status });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

/**
 * GET /api/verify-email
 * note: Подтверждение email пользователя
 * important: Заблокированные пользователи остаются заблокированными
 */
app.get('/api/verify-email', async (req, res) => {
    const { id } = req.query;
    try {
        await db.execute(
            "UPDATE users SET status = 'active' WHERE id = ? AND status != 'blocked'",
            [id]
        );
        res.redirect(`${baseUrl}/login?verified=true`);
    } catch (err) {
        res.status(500).send('Ошибка подтверждения email');
    }
});

/**
 * GET /api/users
 * note: Получение списка пользователей
 * important: requireAuth проверяет blocked/deleted статус
 * nota bene: Сортировка по last_login DESC
 */
app.get('/api/users', requireAuth, async (req, res) => {
    try {
        const [rows] = await db.execute(
            'SELECT id, name, email, status, created_at, last_login FROM users ORDER BY last_login DESC'
        );
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Не удалось получить пользователей' });
    }
});


app.put('/api/users/status', requireAuth, async (req, res) => {
    const { ids, status } = req.body;
    if (!ids || ids.length === 0) {
        return res.status(400).json({ error: 'Пользователи не выбраны' });
    }
    
    try {
        const placeholders = ids.map(() => '?').join(', ');
        await db.execute(
            `UPDATE users SET status = ? WHERE id IN (${placeholders})`, 
            [status, ...ids]
        );
        res.json({ message: `Пользователи ${status === 'blocked' ? 'заблокированы' : 'разблокированы'}.` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Операция не удалась' });
    }
});


app.delete('/api/users', requireAuth, async (req, res) => {
    const { ids } = req.body;
    if (!ids || ids.length === 0) {
        return res.status(400).json({ error: 'Пользователи не выбраны' });
    }

    try {
        const placeholders = ids.map(() => '?').join(', ');
        await db.execute(`DELETE FROM users WHERE id IN (${placeholders})`, ids);
        res.json({ message: 'Пользователи удалены.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Удаление не удалось' });
    }
});


app.delete('/api/users/unverified', requireAuth, async (req, res) => {
    try {
        const [result] = await db.execute("DELETE FROM users WHERE status = 'unverified'");
        res.json({ message: `${result.affectedRows} неподтвержденных пользователей удалено.` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Удаление не удалось' });
    }
});

app.use((req, res) => {
    res.status(404).json({ error: 'Маршрут не найден' });
});

app.listen(3001, () => console.log('Сервер запущен на порту 3001'));
