# TODO

- [x] Унифицировать JWT secret в `middleware.js` через `process.env.JWT_SECRET || 'secret_key'`
- [x] Добавить детальную обработку JWT-ошибок (`TokenExpiredError`, `JsonWebTokenError`) в `middleware.js`
- [x] Улучшить диагностический лог в `middleware.js` (без утечки токена)
- [x] Проверить совместимость с текущим `index.js`
- [ ] Дать итоговые команды проверки (`/api/login` -> `/api/users`)
