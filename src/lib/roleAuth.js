const { descifrarDatos } = require('./encrypDates');

// ==================== ROLE-BASED AUTHENTICATION MIDDLEWARE ====================

// Middleware para verificar si el usuario está logueado
const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    } else {
        req.session.returnTo = req.originalUrl;
        return res.apiError('Authentication required', 401);
    }
};

// Middleware para verificar rol específico
const hasRole = (...allowedRoles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.apiError('Authentication required', 401);
        }

        const userRole = req.user.rolTeacher || req.user.rolStudent || req.user.rolAdmin;
        
        if (!userRole || !allowedRoles.includes(userRole)) {
            return res.apiError(`Access denied. Required roles: ${allowedRoles.join(', ')}`, 403);
        }

        next();
    };
};

// Middleware para verificar tipo de usuario
const hasUserType = (...allowedTypes) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.apiError('Authentication required', 401);
        }

        let userType = '';
        if (req.user.idTeacher) userType = 'teacher';
        else if (req.user.idEstudent) userType = 'student';
        else if (req.user.idAdministrator) userType = 'admin';

        if (!allowedTypes.includes(userType)) {
            return res.apiError(`Access denied. Required user types: ${allowedTypes.join(', ')}`, 403);
        }

        next();
    };
};

// Middleware para verificar si es administrador
const isAdmin = (req, res, next) => {
    if (!req.user) {
        return res.apiError('Authentication required', 401);
    }

    if (!req.user.idAdministrator) {
        return res.apiError('Access denied. Admin privileges required.', 403);
    }

    const adminRoles = ['admin', 'super_admin', 'director', 'coordinator'];
    if (!adminRoles.includes(req.user.rolAdmin)) {
        return res.apiError('Access denied. Admin privileges required.', 403);
    }

    next();
};

// Middleware para verificar si es super administrador
const isSuperAdmin = (req, res, next) => {
    if (!req.user) {
        return res.apiError('Authentication required', 401);
    }

    if (!req.user.idAdministrator || req.user.rolAdmin !== 'super_admin') {
        return res.apiError('Access denied. Super admin privileges required.', 403);
    }

    next();
};

// Middleware para verificar si es profesor
const isTeacher = (req, res, next) => {
    if (!req.user) {
        return res.apiError('Authentication required', 401);
    }

    if (!req.user.idTeacher) {
        return res.apiError('Access denied. Teacher privileges required.', 403);
    }

    next();
};

// Middleware para verificar si es estudiante
const isStudent = (req, res, next) => {
    if (!req.user) {
        return res.apiError('Authentication required', 401);
    }

    if (!req.user.idEstudent) {
        return res.apiError('Access denied. Student privileges required.', 403);
    }

    next();
};

// Middleware para verificar estado de cuenta activo
const isAccountActive = (req, res, next) => {
    if (!req.user) {
        return res.apiError('Authentication required', 401);
    }

    const accountState = req.user.stateTeacher || req.user.stateEstudent || req.user.stateAdmin;
    
    if (accountState !== 'active') {
        return res.apiError(`Account is ${accountState}. Contact administrator.`, 403);
    }

    next();
};

// Middleware para verificar propiedad de recurso (el usuario solo puede acceder a sus propios datos)
const isOwnerOrAdmin = (idParam = 'id') => {
    return (req, res, next) => {
        if (!req.user) {
            return res.apiError('Authentication required', 401);
        }

        const resourceId = req.params[idParam];
        const userId = req.user.idTeacher || req.user.idEstudent || req.user.idAdministrator;
        const isAdmin = req.user.idAdministrator && 
                       ['admin', 'super_admin', 'director'].includes(req.user.rolAdmin);

        // Los admins pueden acceder a cualquier recurso
        if (isAdmin) {
            return next();
        }

        // Los usuarios solo pueden acceder a sus propios recursos
        if (parseInt(resourceId) !== userId) {
            return res.apiError('Access denied. You can only access your own resources.', 403);
        }

        next();
    };
};

// Middleware para agregar información del usuario a req.userInfo (datos descifrados)
const addUserInfo = async (req, res, next) => {
    if (!req.user) {
        return next();
    }

    try {
        let userInfo = {
            id: null,
            type: '',
            role: '',
            state: '',
            username: '',
            name: '',
            email: ''
        };

        if (req.user.idTeacher) {
            userInfo.id = req.user.idTeacher;
            userInfo.type = 'teacher';
            userInfo.role = req.user.rolTeacher;
            userInfo.state = req.user.stateTeacher;
            userInfo.username = req.user.usernameTeahcer;
            userInfo.name = descifrarDatos(req.user.completeNmeTeacher);
            userInfo.email = descifrarDatos(req.user.emailTeacher);
        } else if (req.user.idEstudent) {
            userInfo.id = req.user.idEstudent;
            userInfo.type = 'student';
            userInfo.role = req.user.rolStudent;
            userInfo.state = req.user.stateEstudent;
            userInfo.username = req.user.usernameEstudent;
            userInfo.name = descifrarDatos(req.user.completeNameEstudent);
            userInfo.email = descifrarDatos(req.user.emailEstudent);
        } else if (req.user.idAdministrator) {
            userInfo.id = req.user.idAdministrator;
            userInfo.type = 'admin';
            userInfo.role = req.user.rolAdmin;
            userInfo.state = req.user.stateAdmin;
            userInfo.username = req.user.usernameAdmin;
            userInfo.name = descifrarDatos(req.user.completeNameAdmin);
            userInfo.email = descifrarDatos(req.user.emailAdmin);
        }

        req.userInfo = userInfo;
        next();
    } catch (error) {
        console.error('Error adding user info:', error);
        req.userInfo = null;
        next();
    }
};

// Middleware para logging de accesos
const logAccess = (action = 'access') => {
    return (req, res, next) => {
        if (req.user) {
            const userType = req.user.idTeacher ? 'teacher' : 
                           req.user.idEstudent ? 'student' : 'admin';
            const userId = req.user.idTeacher || req.user.idEstudent || req.user.idAdministrator;
            const username = req.user.usernameTeahcer || req.user.usernameEstudent || req.user.usernameAdmin;
            
            console.log(`[${action.toUpperCase()}] User: ${username} (${userType}:${userId}) - ${req.method} ${req.originalUrl} - IP: ${req.ip}`);
        }
        next();
    };
};

// Middleware para verificar permisos específicos (para administradores)
const hasPermission = (permission) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.apiError('Authentication required', 401);
        }

        if (!req.user.idAdministrator) {
            return res.apiError('Access denied. Admin privileges required.', 403);
        }

        // Super admin tiene todos los permisos
        if (req.user.rolAdmin === 'super_admin') {
            return next();
        }

        // Verificar permisos específicos
        const userPermissions = req.user.permissions || {};
        if (!userPermissions[permission]) {
            return res.apiError(`Access denied. Required permission: ${permission}`, 403);
        }

        next();
    };
};

module.exports = {
    isAuthenticated,
    hasRole,
    hasUserType,
    isAdmin,
    isSuperAdmin,
    isTeacher,
    isStudent,
    isAccountActive,
    isOwnerOrAdmin,
    addUserInfo,
    logAccess,
    hasPermission
};