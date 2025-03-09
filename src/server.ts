import express from 'express';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const saltRounds = 5;

interface User {
    id: string;
    username: string;
    passwordHash: string;
}

// Моковый пользователь
let user: User;
(async () => {
    const passwordHash = await bcrypt.hash('password123', saltRounds);
    user = {
        id: '1',
        username: 'mockUser',
        passwordHash: passwordHash,
};
})();


const SECRET_KEY = 'my_secret_key'; // Ключ для подписи JWT

// Local Strategy (логин и проверка пароля)
passport.use(new LocalStrategy(
  async (username, password, isDone) => {
    if (username !== user.username) {
      return isDone(null, false, { message: 'Неверное имя пользователя' });
    }
    const isValid = await bcrypt.compare(password, user.passwordHash);
    return isValid ? isDone(null, user) : isDone(null, false, { message: 'Неверный пароль' });
  }
));

// JWT Strategy (проверка токена)
passport.use(new JwtStrategy(
  {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: SECRET_KEY,
  },
  (jwtPayload, isDone) => {
    if (jwtPayload.id === user.id) {
      return isDone(null, user);
    }
    return isDone(null, false);
  }
));

const app = express();
app.use(express.json());
app.use(passport.initialize());

// Эндпоинт login (получение JWT)
app.post('/login', (req, res, next) => {
  passport.authenticate('local', { session: false }, (err, user) => {
    if (err || !user) {
      return res.status(400).json({ message: 'Ошибка входа' });
    }
    // Выдача JWT
    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '1h' });
    res.cookie('jwt', token);
    res.json({accessToken: token});
  })(req, res, next);
});

// Эндпоинт profile (требует JWT)
app.get('/profile', passport.authenticate('jwt', { session: false }), (req, res) => {
  res.json({ message: 'Добро пожаловать в профиль!', user: req.user });
});

// Запуск сервера
const PORT = 3000;
app.listen(PORT, () => console.log(`Сервер запущен на http://localhost:${PORT}`));
