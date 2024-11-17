const express = require('express');
const dotenv = require('dotenv');
const employeeRoutes = require('./routes/employeeRoutes');
const { login } = require('./middleware/auth');
const cors = require('cors');


dotenv.config();

const app = express(); // Inicializar `app`

// Middleware
app.use(express.json());
app.use(cors());

// Rutas
app.post('/login', login); // Generar el token
app.use('/api', employeeRoutes); // Usar las rutas de empleados

// Manejo global de errores
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

module.exports = app;