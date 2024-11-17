const express = require('express');
const router = express.Router();
const {
    insertarEmpleado,
    modificarEmpleado,
    eliminarEmpleado,
    consultarEmpleados,
    consultarEmpleadoPorId,
} = require('../controllers/employeeController');
const { authMiddleware } = require('../middleware/auth');


//RUTAS PÚBLICAS
router.get('/employees/public', consultarEmpleados);

// Rutas protegidas
router.use(authMiddleware);

//A PARTIR DE AQUI LAS RUTAS ESTAN PROTEGIDAS
router.get('/employees', consultarEmpleados);
router.get('/employees/:id', consultarEmpleadoPorId);
router.post('/employees', insertarEmpleado);
router.put('/employees/:id', modificarEmpleado);
router.delete('/employees/:id', eliminarEmpleado);

module.exports = router;