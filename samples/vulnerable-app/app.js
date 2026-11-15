// Código DELIBERADAMENTE vulnerable para practicar con el analizador. No usar en producción.
const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');
const app = express();
app.use(cors({ origin: '*' }));                                       // CFG002

app.get('/ping', (req, res) => {
  exec('ping ' + req.query.host, () => res.send('ok'));               // INJ003
});

app.get('/user', (req, res) => {
  db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);          // INJ001
  document.getElementById('x').innerHTML = req.query.name;            // XSS001
  const token = 'tok_' + Math.random().toString(36);                  // CRY003
});

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';                       // CRY002
