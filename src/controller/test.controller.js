const { descifrarDatos } = require('../lib/encrypDates');

const testCtl = {};

// Test endpoint para verificar autenticación básica
testCtl.testAuth = async (req, res) => {
    try {
        if (!req.user) {
            return res.apiError('User not authenticated', 401);
        }

        const userType = req.user.idTeacher ? 'teacher' : 
                        req.user.idEstudent ? 'student' : 'admin';
        
        const username = req.user.usernameTeahcer || req.user.usernameEstudent || req.user.usernameAdmin;

        return res.apiResponse({
            message: 'Authentication successful',
            userType: userType,
            username: username,
            authenticated: true
        }, 200, 'User is authenticated');

    } catch (error) {
        console.error('Test auth error:', error);
        return res.apiError('Internal server error', 500);
    }
};

// Test endpoint para profesores
testCtl.testTeacher = async (req, res) => {
    try {
        const teacherInfo = {
            id: req.user.idTeacher,
            username: req.user.usernameTeahcer,
            role: req.user.rolTeacher,
            state: req.user.stateTeacher,
            name: descifrarDatos(req.user.completeNmeTeacher),
            email: descifrarDatos(req.user.emailTeacher),
            phone: descifrarDatos(req.user.phoneTeacher),
            specialization: req.user.specialization,
            experience: req.user.experience
        };

        return res.apiResponse({
            message: 'Teacher access granted',
            teacherInfo: teacherInfo
        }, 200, 'Teacher authentication successful');

    } catch (error) {
        console.error('Test teacher error:', error);
        return res.apiError('Internal server error', 500);
    }
};

// Test endpoint para estudiantes
testCtl.testStudent = async (req, res) => {
    try {
        const studentInfo = {
            id: req.user.idEstudent,
            username: req.user.usernameEstudent,
            role: req.user.rolStudent,
            state: req.user.stateEstudent,
            name: descifrarDatos(req.user.completeNameEstudent),
            email: descifrarDatos(req.user.emailEstudent),
            phone: descifrarDatos(req.user.celularEstudent),
            location: req.user.ubicationStudent,
            grade: req.user.grade
        };

        return res.apiResponse({
            message: 'Student access granted',
            studentInfo: studentInfo
        }, 200, 'Student authentication successful');

    } catch (error) {
        console.error('Test student error:', error);
        return res.apiError('Internal server error', 500);
    }
};

// Test endpoint para administradores
testCtl.testAdmin = async (req, res) => {
    try {
        const adminInfo = {
            id: req.user.idAdministrator,
            username: req.user.usernameAdmin,
            role: req.user.rolAdmin,
            state: req.user.stateAdmin,
            name: descifrarDatos(req.user.completeNameAdmin),
            email: descifrarDatos(req.user.emailAdmin),
            phone: descifrarDatos(req.user.phoneAdmin),
            department: req.user.department,
            permissions: req.user.permissions,
            lastLogin: req.user.lastLogin
        };

        return res.apiResponse({
            message: 'Admin access granted',
            adminInfo: adminInfo
        }, 200, 'Admin authentication successful');

    } catch (error) {
        console.error('Test admin error:', error);
        return res.apiError('Internal server error', 500);
    }
};

// Test endpoint público (sin autenticación)
testCtl.testPublic = async (req, res) => {
    try {
        return res.apiResponse({
            message: 'This is a public endpoint',
            timestamp: new Date().toISOString(),
            server: 'Sistema Educativo API'
        }, 200, 'Public endpoint access');

    } catch (error) {
        console.error('Test public error:', error);
        return res.apiError('Internal server error', 500);
    }
};

// Test endpoint para verificar cifrado/descifrado
testCtl.testEncryption = async (req, res) => {
    try {
        const { text } = req.body;
        
        if (!text) {
            return res.apiError('Text parameter is required', 400);
        }

        const { cifrarDatos, descifrarDatos } = require('../lib/encrypDates');
        
        const encrypted = cifrarDatos(text);
        const decrypted = descifrarDatos(encrypted);
        
        return res.apiResponse({
            original: text,
            encrypted: encrypted,
            decrypted: decrypted,
            success: text === decrypted
        }, 200, 'Encryption test completed');

    } catch (error) {
        console.error('Test encryption error:', error);
        return res.apiError('Encryption test failed', 500);
    }
};

// Test endpoint para verificar hash de contraseñas
testCtl.testPasswordHash = async (req, res) => {
    try {
        const { password } = req.body;
        
        if (!password) {
            return res.apiError('Password parameter is required', 400);
        }

        const { hashPassword, verifyPassword } = require('../lib/encrypDates');
        
        const hashedPassword = await hashPassword(password);
        const isValid = await verifyPassword(password, hashedPassword);
        
        return res.apiResponse({
            original: password,
            hashed: hashedPassword,
            verified: isValid
        }, 200, 'Password hash test completed');

    } catch (error) {
        console.error('Test password hash error:', error);
        return res.apiError('Password hash test failed', 500);
    }
};

module.exports = testCtl;