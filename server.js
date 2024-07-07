require('dotenv').config();

const express = require('express');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const pool = require('./db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(morgan('dev'));
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY;

// para verificar
function checkCredentials(req, res, next) {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send({ message: 'Email y password son obligatorios.' });
  }
  next();
}

//  para autenticar
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).send({ message: 'Token requerido.' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).send({ message: 'Token inválido.' });
    req.user = user;
    next();
  });
}

// para registrar usuarios
app.post('/usuarios', checkCredentials, async (req, res) => {
  const { email, password, rol, lenguage } = req.body;
  if (!rol || !lenguage) {
    return res.status(400).send({ message: 'Todos los campos son obligatorios.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4) RETURNING *',
      [email, hashedPassword, rol, lenguage]
    );
    res.status(201).send(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Error al registrar el usuario.' });
  }
});

// para iniciar sesión y generar un token
app.post('/login', checkCredentials, async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).send({ message: 'Usuario no encontrado.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).send({ message: 'Contraseña incorrecta.' });
    }

    const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: '1h' });
    res.status(200).send({ token });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Error al iniciar sesión.' });
  }
});

// para obtener losdatos del usuario
app.get('/usuarios', authenticateToken, async (req, res) => {
  const { email } = req.user;

  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    res.status(200).send(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Error al obtener datos del usuario.' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
