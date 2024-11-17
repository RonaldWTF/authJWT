const pool = require('../config/db');

// Insertar empleado
async function insertarEmpleado(req, res) {
    const { first_name, last_name, email, phone_number, hire_date, job_id, salary, commission_pct, manager_id, department_id } = req.body;

    const query = `INSERT INTO employees (
        first_name, last_name, email, phone_number, hire_date, job_id, salary, commission_pct, manager_id, department_id
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`;

    const values = [first_name, last_name, email, phone_number, hire_date, job_id, salary, commission_pct, manager_id, department_id];

    try {
        const result = await pool.query(query, values);
        res.status(201).json({ message: 'Employee successfully created', employee_id: result.insertId });
    } catch (err) {
        console.error('Error creating employee:', err);
        res.status(500).json({ error: 'Server error' });
    }
}

// Modificar empleado
async function modificarEmpleado(req, res) {
    const { id } = req.params;
    const { first_name, last_name, email, phone_number, hire_date, job_id, salary, commission_pct, manager_id, department_id } = req.body;

    const query = `UPDATE employees
    SET first_name = $2, last_name = $3, email = $4, phone_number = $5, hire_date = $6, job_id = $7,
    salary = $8, commission_pct = $9, manager_id = $10, department_id = $11
    WHERE employee_id = $1`;

    const values = [id, first_name, last_name, email, phone_number, hire_date, job_id, salary, commission_pct, manager_id, department_id];

    try {
        const result = await pool.query(query, values);

        if (result.rowCount > 0) {
            res.status(200).json({ message: 'Employee successfully updated' });
        } else {
            res.status(404).json({ error: 'Employee not found' });
        }
    } catch (err) {
        console.error('Error updating employee:', err);
        res.status(500).json({ error: 'Server error' });
    }
}

// Eliminar empleado
async function eliminarEmpleado(req, res) {
    const { id } = req.params;

    const query = 'DELETE FROM employees WHERE employee_id = $1';
    const values = [id];

    try {
        const result = await pool.query(query, values);

        if (result.rowCount > 0) {
            res.status(200).json({ message: 'Employee successfully deleted' });
        } else {
            res.status(404).json({ error: 'Employee not found' });
        }
    } catch (err) {
        console.error('Error deleting employee:', err);
        res.status(500).json({ error: 'Server error' });
    }
}

// Consultar todos los empleados
async function consultarEmpleados(req, res) {
    const query = 'SELECT * FROM employees';

    try {
        const result = await pool.query(query);
        res.status(200).json(result.rows);
    } catch (err) {
        console.error('Error fetching employees:', err);
        res.status(500).json({ error: 'Server error' });
    }
}

// Consultar empleado por ID
async function consultarEmpleadoPorId(req, res) {
    const { id } = req.params;

    const query = 'SELECT * FROM employees WHERE employee_id = $1';
    const values = [id];

    try {
        const result = await pool.query(query, values);

        if (result.rows.length > 0) {
            res.status(200).json(result.rows[0]);
        } else {
            res.status(404).json({ error: 'Employee not found' });
        }
    } catch (err) {
        console.error('Error fetching employee by ID:', err);
        res.status(500).json({ error: 'Server error' });
    }
}

module.exports = {
    insertarEmpleado,
    modificarEmpleado,
    eliminarEmpleado,
    consultarEmpleados,
    consultarEmpleadoPorId,
};