const express = require('express');
const router = express.Router();
const testCtl = require('../controller/test.controller');
const { isAuthenticated, isTeacher, isStudent, isAdmin, addUserInfo } = require('../lib/roleAuth');

// ==================== PUBLIC TEST ENDPOINTS ====================

// Test público (sin autenticación)
router.get('/public', testCtl.testPublic);

// Test de cifrado/descifrado
router.post('/encryption', testCtl.testEncryption);

// Test de hash de contraseñas
router.post('/password-hash', testCtl.testPasswordHash);

// ==================== AUTHENTICATED TEST ENDPOINTS ====================

// Test de autenticación básica (cualquier usuario logueado)
router.get('/auth', isAuthenticated, addUserInfo, testCtl.testAuth);

// Test específico para profesores
router.get('/teacher', isAuthenticated, isTeacher, testCtl.testTeacher);

// Test específico para estudiantes
router.get('/student', isAuthenticated, isStudent, testCtl.testStudent);

// Test específico para administradores
router.get('/admin', isAuthenticated, isAdmin, testCtl.testAdmin);

// ==================== INFO ENDPOINTS ====================

// Endpoint para obtener información del servidor
router.get('/server-info', (req, res) => {
    try {
        return res.apiResponse({
            server: 'Sistema Educativo API',
            version: '1.0.0',
            environment: process.env.NODE_ENV || 'development',
            timestamp: new Date().toISOString(),
            uptime: process.uptime(),
            memoryUsage: process.memoryUsage(),
            endpoints: {
                authentication: {
                    login: 'POST /auth/api/login',
                    register_student: 'POST /auth/register/student',
                    register_teacher: 'POST /auth/register/teacher',
                    profile: 'GET /auth/api/profile',
                    logout: 'POST /auth/api/logout'
                },
                tests: {
                    public: 'GET /test/public',
                    auth: 'GET /test/auth (requires authentication)',
                    teacher: 'GET /test/teacher (requires teacher role)',
                    student: 'GET /test/student (requires student role)',
                    admin: 'GET /test/admin (requires admin role)',
                    encryption: 'POST /test/encryption',
                    password_hash: 'POST /test/password-hash'
                }
            }
        }, 200, 'Server information retrieved successfully');
    } catch (error) {
        console.error('Server info error:', error);
        return res.apiError('Internal server error', 500);
    }
});

// Endpoint para verificar estado de la base de datos
router.get('/db-status', async (req, res) => {
    try {
        const orm = require('../Database/dataBase.orm');
        
        // Test simple de conexión
        const teacherCount = await orm.teacher.count();
        const studentCount = await orm.student.count();
        const adminCount = await orm.administrator.count();
        
        return res.apiResponse({
            database: 'Connected',
            models: {
                teachers: teacherCount,
                students: studentCount,
                administrators: adminCount
            },
            timestamp: new Date().toISOString()
        }, 200, 'Database status retrieved successfully');
        
    } catch (error) {
        console.error('Database status error:', error);
        return res.apiError('Database connection failed', 500, error.message);
    }
});

module.exports = router;