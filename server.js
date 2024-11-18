require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
app.use(bodyParser.json());

const port = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.send('Servidor funcionando! 🚀');
});

const users = [
  {
    username: 'user',
    password: bcrypt.hashSync('123456', 10),
    email: 'user@dominio.com',
    perfil: 'user',
  },
  {
    username: 'admin',
    password: bcrypt.hashSync('123456789', 10),
    id: 124,
    email: 'admin@dominio.com',
    perfil: 'admin',
  },
];

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token ausente ou inválido' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token inválido ou expirado' });
    req.user = user;
    next();
  });
};

const authorizeAdmin = (req, res, next) => {
  if (req.user.perfil !== 'admin') {
    return res.status(403).json({ message: 'Acesso restrito para administradores' });
  }
  next();
};

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ message: 'Credenciais inválidas' });
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, perfil: user.perfil },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  res.json({ token });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.status(200).json({ user: req.user });
});

app.get('/api/users', authenticateToken, authorizeAdmin, (req, res) => {
  res.status(200).json({ data: users });
});

app.get('/api/contracts', authenticateToken, authorizeAdmin, (req, res) => {
  const { empresa, inicio } = req.query;

  if (!empresa || !inicio) {
    return res.status(400).json({ message: 'Parâmetros obrigatórios ausentes' });
  }

  if (!/^[a-zA-Z0-9_-]+$/.test(empresa) || !/^\d{4}-\d{2}-\d{2}$/.test(inicio)) {
    return res.status(400).json({ message: 'Parâmetros inválidos' });
  }

  const contracts = [
    { empresa: 'ABCCorp', inicio: '2023-01-01', contrato: 'Contrato 1' },
    { empresa: 'XYZLtd', inicio: '2023-02-01', contrato: 'Contrato 2' },
  ];

  const result = contracts.filter(
    (c) => c.empresa === empresa && c.inicio === inicio
  );

  if (result.length === 0) {
    return res.status(404).json({ message: 'Nenhum contrato encontrado' });
  }

  res.status(200).json({ data: result });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
