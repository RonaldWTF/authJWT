const jwt = require('jsonwebtoken');
const pool = require('../config/db');
const dotenv = require('dotenv');

dotenv.config(); // Carga las variables de entorno desde .env

// Middleware para verificar autenticación
const authMiddleware = (req, res, next) => {
    const authHeader = req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token not provided or malformed' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }
};


// Endpoint de login
const login = async(req, res) => {
    const { username, password } = req.body; // Obtenemos las credenciales del cuerpo de la solicitud

    // Consulta para buscar el usuario en la base de datos
    const query = 'SELECT * FROM users WHERE username = $1 AND password = $2';
    const values = [username, password];

    try {
        const result = await pool.query(query, values);

        // Si no se encuentra el usuario, devolver un error
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        // Si se encuentra el usuario, generamos un token JWT
        const user = result.rows[0];
        const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.json({ message: 'Login successful', token });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Server error' });
    }
};


module.exports = {
    authMiddleware,
    login,
};