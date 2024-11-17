const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('../config/db');

exports.login = async(req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    try {
        console.log('Usuario enviado:', username);
        console.log('Contraseña enviada:', password);

        // Buscar el usuario en la base de datos
        const query = 'SELECT * FROM users WHERE username = $1';
        const result = await pool.query(query, [username]);
        console.log('Resultado de la consulta:', result.rows);

        if (result.rows.length === 0) {
            console.log('El usuario no existe');
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const user = result.rows[0];
        console.log('Usuario encontrado:', user);

        // Comparar contraseñas
        const isPasswordValid = await bcrypt.compare(password, user.password);
        console.log('Contraseña válida:', isPasswordValid);

        if (!isPasswordValid) {
            console.log('La contraseña no coincide');
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Generar token
        const token = jwt.sign({ id: user.id, username: user.username },
            process.env.JWT_SECRET, { expiresIn: '1h' }
        );

        console.log('Login exitoso');
        res.json({ message: 'Login successful', token });
    } catch (error) {
        console.error('Error durante el login:', error);
        res.status(500).json({ message: 'Server error' });
    }
};