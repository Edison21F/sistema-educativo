const passport = require('passport');
const { validationResult } = require('express-validator');
const orm = require('../Database/dataBase.orm');
const sql = require('../Database/dataBase.sql');
const { 
    cifrarDatos, 
    descifrarDatos, 
    hashPassword, 
    verifyPassword,
    cifrarCampos,
    descifrarCampos,
    sanitizarEntrada 
} = require('../lib/encrypDates');

const authCtl = {};

// ==================== LOGIN CONTROLLERS ====================

// Login Teacher
authCtl.loginTeacher = passport.authenticate('local.teacherSignin', {
    successRedirect: '/dashboard/teacher',
    failureRedirect: '/login/teacher',
    failureFlash: true,
    failureMessage: true
});

// Login Student
authCtl.loginStudent = passport.authenticate('local.studentSignin', {
    successRedirect: '/dashboard/student',
    failureRedirect: '/login/student',
    failureFlash: true,
    failureMessage: true
});

// Login Administrator
authCtl.loginAdmin = passport.authenticate('local.adminSignin', {
    successRedirect: '/dashboard/admin',
    failureRedirect: '/login/admin',
    failureFlash: true,
    failureMessage: true
});

// ==================== REGISTRATION CONTROLLERS ====================

// Register Teacher
authCtl.registerTeacher = passport.authenticate('local.teacherSignup', {
    successRedirect: '/profile/teacher',
    failureRedirect: '/register/teacher',
    failureFlash: true,
    failureMessage: true
});

// Register Student
authCtl.registerStudent = passport.authenticate('local.studentSignup', {
    successRedirect: '/profile/student',
    failureRedirect: '/register/student',
    failureFlash: true,
    failureMessage: true
});

// Register Administrator (only by super admin)
authCtl.registerAdmin = passport.authenticate('local.adminSignup', {
    successRedirect: '/admin/users',
    failureRedirect: '/register/admin',
    failureFlash: true,
    failureMessage: true
});

// ==================== API LOGIN CONTROLLERS ====================

// API Login for any user type
authCtl.apiLogin = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.apiError('Validation errors', 400, errors.array());
        }

        const { username, password, userType } = req.body;

        if (!username || !password || !userType) {
            return res.apiError('Username, password, and userType are required', 400);
        }

        // Sanitizar entrada
        const sanitizedUsername = sanitizarEntrada(username);
        const sanitizedUserType = sanitizarEntrada(userType);

        let user = null;
        let model = null;
        let usernameField = '';
        let passwordField = '';

        // Determinar modelo y campos según tipo de usuario
        switch (sanitizedUserType) {
            case 'teacher':
                model = orm.teacher;
                usernameField = 'usernameTeahcer';
                passwordField = 'passwordTeacher';
                break;
            case 'student':
                model = orm.student;
                usernameField = 'usernameEstudent';
                passwordField = 'passwordEstudent';
                break;
            case 'admin':
                model = orm.administrator;
                usernameField = 'usernameAdmin';
                passwordField = 'passwordAdmin';
                break;
            default:
                return res.apiError('Invalid user type', 400);
        }

        // Buscar usuario
        user = await model.findOne({
            where: { [usernameField]: sanitizedUsername }
        });

        if (!user) {
            return res.apiError('Invalid credentials', 401);
        }

        // Verificar contraseña
        const isPasswordValid = await verifyPassword(password, user[passwordField]);
        if (!isPasswordValid) {
            return res.apiError('Invalid credentials', 401);
        }

        // Verificar estado del usuario
        const stateField = sanitizedUserType === 'teacher' ? 'stateTeacher' : 
                          sanitizedUserType === 'student' ? 'stateEstudent' : 'stateAdmin';
        
        if (user[stateField] !== 'active') {
            return res.apiError(`Account is ${user[stateField]}. Contact administrator.`, 403);
        }

        // Actualizar último login si es admin
        if (sanitizedUserType === 'admin') {
            await model.update(
                { lastLogin: new Date() },
                { where: { [usernameField]: sanitizedUsername } }
            );
        }

        // Crear sesión
        req.login(user, (err) => {
            if (err) {
                return res.apiError('Login failed', 500);
            }

            // Preparar datos del usuario (sin información sensible)
            const userData = {
                id: user[`id${sanitizedUserType.charAt(0).toUpperCase() + sanitizedUserType.slice(1)}`] || user.idTeacher || user.idEstudent || user.idAdministrator,
                username: user[usernameField],
                userType: sanitizedUserType,
                role: user[`rol${sanitizedUserType.charAt(0).toUpperCase() + sanitizedUserType.slice(1)}`] || user.rolTeacher || user.rolStudent || user.rolAdmin,
                state: user[stateField]
            };

            return res.apiResponse(userData, 200, 'Login successful');
        });

    } catch (error) {
        console.error('API Login error:', error);
        return res.apiError('Internal server error', 500);
    }
};

// ==================== PROFILE MANAGEMENT ====================

// Get user profile
authCtl.getProfile = async (req, res) => {
    try {
        if (!req.user) {
            return res.apiError('User not authenticated', 401);
        }

        const userId = req.user.idTeacher || req.user.idEstudent || req.user.idAdministrator;
        const userType = req.user.rolTeacher ? 'teacher' : 
                        req.user.rolStudent ? 'student' : 'admin';

        let model = null;
        let encryptedFields = [];

        switch (userType) {
            case 'teacher':
                model = orm.teacher;
                encryptedFields = ['identificationCardTeacher', 'completeNmeTeacher', 'emailTeacher', 'phoneTeacher'];
                break;
            case 'student':
                model = orm.student;
                encryptedFields = ['identificationCardStudent', 'completeNameEstudent', 'emailEstudent', 'celularEstudent', 'guardianName', 'guardianPhone'];
                break;
            case 'admin':
                model = orm.administrator;
                encryptedFields = ['identificationCardAdmin', 'completeNameAdmin', 'emailAdmin', 'phoneAdmin'];
                break;
        }

        const user = await model.findByPk(userId);
        if (!user) {
            return res.apiError('User not found', 404);
        }

        // Descifrar campos sensibles
        const userProfile = descifrarCampos(user.toJSON(), encryptedFields);
        
        // Remover contraseña del resultado
        const passwordField = userType === 'teacher' ? 'passwordTeacher' : 
                             userType === 'student' ? 'passwordEstudent' : 'passwordAdmin';
        delete userProfile[passwordField];

        return res.apiResponse(userProfile, 200, 'Profile retrieved successfully');

    } catch (error) {
        console.error('Get profile error:', error);
        return res.apiError('Internal server error', 500);
    }
};

// Update user profile
authCtl.updateProfile = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.apiError('Validation errors', 400, errors.array());
        }

        if (!req.user) {
            return res.apiError('User not authenticated', 401);
        }

        const userId = req.user.idTeacher || req.user.idEstudent || req.user.idAdministrator;
        const userType = req.user.rolTeacher ? 'teacher' : 
                        req.user.rolStudent ? 'student' : 'admin';

        let model = null;
        let encryptedFields = [];
        let updateData = {};

        switch (userType) {
            case 'teacher':
                model = orm.teacher;
                encryptedFields = ['identificationCardTeacher', 'completeNmeTeacher', 'emailTeacher', 'phoneTeacher'];
                updateData = {
                    completeNmeTeacher: req.body.completeNmeTeacher,
                    emailTeacher: req.body.emailTeacher,
                    phoneTeacher: req.body.phoneTeacher,
                    specialization: req.body.specialization,
                    experience: req.body.experience,
                    updateTeacher: new Date().toLocaleString()
                };
                break;
            case 'student':
                model = orm.student;
                encryptedFields = ['completeNameEstudent', 'emailEstudent', 'celularEstudent', 'guardianName', 'guardianPhone'];
                updateData = {
                    completeNameEstudent: req.body.completeNameEstudent,
                    emailEstudent: req.body.emailEstudent,
                    celularEstudent: req.body.celularEstudent,
                    ubicationStudent: req.body.ubicationStudent,
                    grade: req.body.grade,
                    guardianName: req.body.guardianName,
                    guardianPhone: req.body.guardianPhone,
                    updateStudent: new Date().toLocaleString()
                };
                break;
            case 'admin':
                model = orm.administrator;
                encryptedFields = ['completeNameAdmin', 'emailAdmin', 'phoneAdmin'];
                updateData = {
                    completeNameAdmin: req.body.completeNameAdmin,
                    emailAdmin: req.body.emailAdmin,
                    phoneAdmin: req.body.phoneAdmin,
                    department: req.body.department,
                    updateAdmin: new Date().toLocaleString()
                };
                break;
        }

        // Filtrar y sanitizar campos no nulos
        Object.keys(updateData).forEach(key => {
            if (updateData[key] === undefined || updateData[key] === null) {
                delete updateData[key];
            } else if (typeof updateData[key] === 'string') {
                updateData[key] = sanitizarEntrada(updateData[key]);
            }
        });

        // Cifrar campos sensibles
        const encryptedUpdateData = cifrarCampos(updateData, encryptedFields);

        // Actualizar usuario
        await model.update(encryptedUpdateData, {
            where: { [`id${userType.charAt(0).toUpperCase() + userType.slice(1)}`]: userId }
        });

        return res.apiResponse(null, 200, 'Profile updated successfully');

    } catch (error) {
        console.error('Update profile error:', error);
        return res.apiError('Internal server error', 500);
    }
};

// Change password
authCtl.changePassword = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.apiError('Validation errors', 400, errors.array());
        }

        if (!req.user) {
            return res.apiError('User not authenticated', 401);
        }

        const { currentPassword, newPassword, confirmPassword } = req.body;

        if (newPassword !== confirmPassword) {
            return res.apiError('New passwords do not match', 400);
        }

        const userId = req.user.idTeacher || req.user.idEstudent || req.user.idAdministrator;
        const userType = req.user.rolTeacher ? 'teacher' : 
                        req.user.rolStudent ? 'student' : 'admin';

        let model = null;
        let passwordField = '';

        switch (userType) {
            case 'teacher':
                model = orm.teacher;
                passwordField = 'passwordTeacher';
                break;
            case 'student':
                model = orm.student;
                passwordField = 'passwordEstudent';
                break;
            case 'admin':
                model = orm.administrator;
                passwordField = 'passwordAdmin';
                break;
        }

        // Verificar contraseña actual
        const user = await model.findByPk(userId);
        const isCurrentPasswordValid = await verifyPassword(currentPassword, user[passwordField]);
        
        if (!isCurrentPasswordValid) {
            return res.apiError('Current password is incorrect', 400);
        }

        // Hash nueva contraseña
        const hashedNewPassword = await hashPassword(newPassword);

        // Actualizar contraseña
        await model.update(
            { [passwordField]: hashedNewPassword },
            { where: { [`id${userType.charAt(0).toUpperCase() + userType.slice(1)}`]: userId } }
        );

        return res.apiResponse(null, 200, 'Password changed successfully');

    } catch (error) {
        console.error('Change password error:', error);
        return res.apiError('Internal server error', 500);
    }
};

// ==================== SESSION MANAGEMENT ====================

// Logout
authCtl.logout = (req, res) => {
    req.logout((err) => {
        if (err) {
            return res.apiError('Logout failed', 500);
        }
        req.session.destroy((err) => {
            if (err) {
                return res.apiError('Session cleanup failed', 500);
            }
            res.clearCookie('connect.sid');
            return res.apiResponse(null, 200, 'Logged out successfully');
        });
    });
};

// Check authentication status
authCtl.checkAuth = (req, res) => {
    if (req.isAuthenticated()) {
        const userType = req.user.rolTeacher ? 'teacher' : 
                        req.user.rolStudent ? 'student' : 'admin';
        const userId = req.user.idTeacher || req.user.idEstudent || req.user.idAdministrator;
        
        return res.apiResponse({
            authenticated: true,
            userType,
            userId,
            username: req.user.usernameTeahcer || req.user.usernameEstudent || req.user.usernameAdmin
        }, 200, 'User is authenticated');
    } else {
        return res.apiResponse({
            authenticated: false
        }, 200, 'User is not authenticated');
    }
};

module.exports = authCtl;