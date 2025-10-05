const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const authCtl = require('../controller/auth.controller');
const isLoggedIn = require('../lib/auth');
const orm = require('../Database/dataBase.orm');
const { descifrarCampos } = require('../lib/encrypDates');

// ==================== VALIDATION MIDDLEWARE ====================

// Validación para login
const loginValidation = [
    body('username')
        .notEmpty()
        .withMessage('Username is required')
        .isLength({ min: 3, max: 50 })
        .withMessage('Username must be between 3 and 50 characters')
        .matches(/^[a-zA-Z0-9_.-]+$/)
        .withMessage('Username can only contain letters, numbers, dots, hyphens and underscores'),
    
    body('password')
        .notEmpty()
        .withMessage('Password is required')
        .isLength({ min: 6 })
        .withMessage('Password must be at least 6 characters long'),
    
    body('userType')
        .isIn(['teacher', 'student', 'admin'])
        .withMessage('User type must be teacher, student, or admin')
];

// Validación para registro de estudiante
const studentRegisterValidation = [
    body('username')
        .notEmpty()
        .withMessage('Username is required')
        .isLength({ min: 3, max: 50 })
        .withMessage('Username must be between 3 and 50 characters')
        .matches(/^[a-zA-Z0-9_.-]+$/)
        .withMessage('Username can only contain letters, numbers, dots, hyphens and underscores'),
    
    body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
        .withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number'),
    
    body('identificationCard')
        .notEmpty()
        .withMessage('Identification card is required')
        .isLength({ min: 5, max: 20 })
        .withMessage('Identification card must be between 5 and 20 characters'),
    
    body('completeNameEstudent')
        .notEmpty()
        .withMessage('Full name is required')
        .isLength({ min: 2, max: 100 })
        .withMessage('Full name must be between 2 and 100 characters')
        .matches(/^[a-zA-ZÀ-ÿ\s]+$/)
        .withMessage('Full name can only contain letters and spaces'),
    
    body('emailEstudent')
        .isEmail()
        .withMessage('Please provide a valid email address')
        .normalizeEmail(),
    
    body('celularEstudent')
        .matches(/^\+?[1-9]\d{1,14}$/)
        .withMessage('Please provide a valid phone number')
];

// Validación para registro de profesor
const teacherRegisterValidation = [
    body('username')
        .notEmpty()
        .withMessage('Username is required')
        .isLength({ min: 3, max: 50 })
        .withMessage('Username must be between 3 and 50 characters')
        .matches(/^[a-zA-Z0-9_.-]+$/)
        .withMessage('Username can only contain letters, numbers, dots, hyphens and underscores'),
    
    body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
        .withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number'),
    
    body('identificationCard')
        .notEmpty()
        .withMessage('Identification card is required')
        .isLength({ min: 5, max: 20 })
        .withMessage('Identification card must be between 5 and 20 characters'),
    
    body('completeNmeTeacher')
        .notEmpty()
        .withMessage('Full name is required')
        .isLength({ min: 2, max: 100 })
        .withMessage('Full name must be between 2 and 100 characters')
        .matches(/^[a-zA-ZÀ-ÿ\s]+$/)
        .withMessage('Full name can only contain letters and spaces'),
    
    body('emailTeacher')
        .isEmail()
        .withMessage('Please provide a valid email address')
        .normalizeEmail(),
    
    body('phoneTeacher')
        .matches(/^\+?[1-9]\d{1,14}$/)
        .withMessage('Please provide a valid phone number')
];

// Validación para cambio de contraseña
const changePasswordValidation = [
    body('currentPassword')
        .notEmpty()
        .withMessage('Current password is required'),
    
    body('newPassword')
        .isLength({ min: 8 })
        .withMessage('New password must be at least 8 characters long')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
        .withMessage('New password must contain at least one lowercase letter, one uppercase letter, and one number'),
    
    body('confirmPassword')
        .custom((value, { req }) => {
            if (value !== req.body.newPassword) {
                throw new Error('Password confirmation does not match password');
            }
            return true;
        })
];

// ==================== AUTHENTICATION ROUTES ====================

// API Login route
router.post('/api/login', loginValidation, authCtl.apiLogin);

// Traditional form-based login routes
router.post('/login/teacher', authCtl.loginTeacher);
router.post('/login/student', authCtl.loginStudent);
router.post('/login/admin', authCtl.loginAdmin);

// Registration routes
router.post('/register/student', studentRegisterValidation, authCtl.registerStudent);
router.post('/register/teacher', teacherRegisterValidation, authCtl.registerTeacher);
router.post('/register/admin', isLoggedIn, authCtl.registerAdmin); // Solo admins logueados

// ==================== PROFILE MANAGEMENT ROUTES ====================

// Get user profile
router.get('/api/profile', isLoggedIn, authCtl.getProfile);

// Update user profile
router.put('/api/profile', isLoggedIn, authCtl.updateProfile);

// Change password
router.post('/api/change-password', isLoggedIn, changePasswordValidation, authCtl.changePassword);

// ==================== SESSION MANAGEMENT ROUTES ====================

// Logout
router.post('/api/logout', authCtl.logout);
router.post('/logout', authCtl.logout); // Traditional logout

// Check authentication status
router.get('/api/auth-status', authCtl.checkAuth);

// ==================== USER MANAGEMENT ROUTES (Admin only) ====================

// Middleware para verificar rol de administrador
const isAdmin = (req, res, next) => {
    if (req.user && (req.user.rolAdmin === 'admin' || req.user.rolAdmin === 'super_admin' || req.user.rolAdmin === 'director')) {
        return next();
    }
    return res.apiError('Access denied. Admin privileges required.', 403);
};

// Obtener usuarios por tipo (solo admins)
router.get('/api/users/:userType', isLoggedIn, isAdmin, async (req, res) => {
    try {
        const { userType } = req.params;
        const { page = 1, limit = 10, search = '', status = '' } = req.query;
        
        let model = null;
        let encryptedFields = [];
        
        switch (userType) {
            case 'teachers':
                model = orm.teacher;
                encryptedFields = ['identificationCardTeacher', 'completeNmeTeacher', 'emailTeacher', 'phoneTeacher'];
                break;
            case 'students':
                model = orm.student;
                encryptedFields = ['identificationCardStudent', 'completeNameEstudent', 'emailEstudent', 'celularEstudent'];
                break;
            case 'admins':
                model = orm.administrator;
                encryptedFields = ['identificationCardAdmin', 'completeNameAdmin', 'emailAdmin', 'phoneAdmin'];
                break;
            default:
                return res.apiError('Invalid user type', 400);
        }
        
        // Construir condiciones de búsqueda
        let whereCondition = {};
        if (status) {
            const stateField = userType === 'teachers' ? 'stateTeacher' : 
                              userType === 'students' ? 'stateEstudent' : 'stateAdmin';
            whereCondition[stateField] = status;
        }
        
        // Obtener usuarios con paginación
        const offset = (page - 1) * limit;
        const users = await model.findAndCountAll({
            where: whereCondition,
            limit: parseInt(limit),
            offset: parseInt(offset),
            order: [['createdAt', 'DESC']]
        });
        
        // Descifrar datos sensibles
        const decryptedUsers = users.rows.map(user => {
            const userData = user.toJSON();
            const decryptedData = descifrarCampos(userData, encryptedFields);
            
            // Remover contraseña
            const passwordField = userType === 'teachers' ? 'passwordTeacher' : 
                                 userType === 'students' ? 'passwordEstudent' : 'passwordAdmin';
            delete decryptedData[passwordField];
            
            return decryptedData;
        });
        
        // Filtrar por búsqueda si se proporciona
        let filteredUsers = decryptedUsers;
        if (search) {
            const searchLower = search.toLowerCase();
            filteredUsers = decryptedUsers.filter(user => {
                const nameField = userType === 'teachers' ? user.completeNmeTeacher : 
                                 userType === 'students' ? user.completeNameEstudent : user.completeNameAdmin;
                const usernameField = userType === 'teachers' ? user.usernameTeahcer : 
                                     userType === 'students' ? user.usernameEstudent : user.usernameAdmin;
                
                return nameField?.toLowerCase().includes(searchLower) || 
                       usernameField?.toLowerCase().includes(searchLower);
            });
        }
        
        return res.apiResponse({
            users: filteredUsers,
            pagination: {
                total: users.count,
                page: parseInt(page),
                limit: parseInt(limit),
                totalPages: Math.ceil(users.count / limit)
            }
        }, 200, 'Users retrieved successfully');
        
    } catch (error) {
        console.error('Get users error:', error);
        return res.apiError('Internal server error', 500);
    }
});

// Activar/Desactivar usuario (solo admins)
router.patch('/api/users/:userType/:id/status', isLoggedIn, isAdmin, async (req, res) => {
    try {
        const { userType, id } = req.params;
        const { status } = req.body;
        
        if (!['active', 'inactive', 'suspended', 'pending'].includes(status)) {
            return res.apiError('Invalid status', 400);
        }
        
        let model = null;
        let stateField = '';
        let idField = '';
        
        switch (userType) {
            case 'teachers':
                model = orm.teacher;
                stateField = 'stateTeacher';
                idField = 'idTeacher';
                break;
            case 'students':
                model = orm.student;
                stateField = 'stateEstudent';
                idField = 'idEstudent';
                break;
            case 'admins':
                model = orm.administrator;
                stateField = 'stateAdmin';
                idField = 'idAdministrator';
                break;
            default:
                return res.apiError('Invalid user type', 400);
        }
        
        await model.update(
            { [stateField]: status },
            { where: { [idField]: id } }
        );
        
        return res.apiResponse(null, 200, 'User status updated successfully');
        
    } catch (error) {
        console.error('Update user status error:', error);
        return res.apiError('Internal server error', 500);
    }
});

module.exports = router;