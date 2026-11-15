// Ejemplo mínimo de servidor Express con controles de seguridad básicos.
// npm i express helmet express-rate-limit cors zod jsonwebtoken
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { z } = require('zod');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET; // desde un gestor de secretos, nunca en el código
if (!JWT_SECRET) throw new Error('JWT_SECRET requerido');

app.disable('x-powered-by');
app.use(helmet());                                   // headers de seguridad + CSP
app.use(cors({ origin: ['https://app.example.com'] })); // orígenes explícitos
app.use(express.json({ limit: '100kb' }));            // límite de tamaño

// Rate limiting global y más estricto en login
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 300 }));
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });

// Middleware de autenticación (verifica el token en el servidor)
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    next();
  } catch {
    res.status(401).json({ error: 'No autorizado' });
  }
}

// Middleware de autorización por rol (deny by default)
const requireRole = (role) => (req, res, next) =>
  req.user?.roles?.includes(role) ? next() : res.status(403).json({ error: 'Prohibido' });

// Validación con esquema
const loginSchema = z.object({ user: z.string().min(1).max(64), password: z.string().min(1).max(128) });

app.post('/auth/login', loginLimiter, (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Datos inválidos' });
  // Verifica credenciales con Argon2id/bcrypt aquí. Mensaje genérico si falla.
  res.status(401).json({ error: 'Credenciales inválidas' });
});

// El actor sale del token, no del body
app.post('/api/items', auth, requireRole('editor'), (req, res) => {
  const actor = req.user.sub;
  res.json({ ok: true, actor });
});

// Manejo de errores genérico
app.use((err, req, res, next) => {
  console.error(err);                       // detalle solo en logs
  res.status(500).json({ error: 'Error interno' });
});

app.listen(3000);
