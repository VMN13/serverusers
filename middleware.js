const jwt = require('jsonwebtoken');
const db = require('./db');

// important: Используем тот же secret что в .env
const JWT_SECRET = 'my_secret_key_123';

async function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Требуется авторизация' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const payload = jwt.verify(token, JWT_SECRET);
        
        const [rows] = await db.execute(
            'SELECT id, status FROM users WHERE id = ?',
            [payload.id]
        );

        if (rows.length === 0) {
            return res.status(401).json({ error: 'Пользователь удален' });
        }

        if (rows[0].status === 'blocked') {
            return res.status(403).json({ error: 'Пользователь заблокирован' });
        }

        req.user = payload;
        next();
    } catch (err) {
        console.error('Auth error:', err);
        return res.status(401).json({ error: 'Недействительный токен' });
    }
}

module.exports = { requireAuth };