const { descifrarDatos } = require('./encrypDates');

// ==================== ROLE-BASED AUTHENTICATION MIDDLEWARE ====================

// Middleware básico de autenticación
const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    
    // Para API requests
    if (req.originalUrl.startsWith('/api/') || req.headers.accept?.includes('application/json')) {
        return res.apiError('Authentication required', 401);
    }
    
    // Para requests tradicionales
    req.session.returnTo = req.originalUrl;
    return res.redirect('/login');
};

// Middleware para verificar si el usuario es un estudiante
const isStudent = (req, res, next) => {
    if (!req.user) {
        return res.apiError('Authentication required', 401);
    }
    
    if (req.user.rolStudent || req.user.idEstudent) {
        return next();
    }
    
    return res.apiError('Student access required', 403);
};

// Middleware para verificar si el usuario es un profesor
const isTeacher = (req, res, next) => {
    if (!req.user) {
        return res.apiError('Authentication required', 401);
    }
    
    if (req.user.rolTeacher || req.user.idTeacher) {
        return next();
    }
    
    return res.apiError('Teacher access required', 403);
};

// Middleware para verificar si el usuario es un administrador
const isAdmin = (req, res, next) => {
    if (!req.user) {
        return res.apiError('Authentication required', 401);
    }
    
    if (req.user.rolAdmin || req.user.idAdministrator) {
        return next();
    }
    
    return res.apiError('Administrator access required', 403);
};

// Middleware para verificar si el usuario es un super administrador
const isSuperAdmin = (req, res, next) => {
    if (!req.user) {
        return res.apiError('Authentication required', 401);
    }
    
    if (req.user.rolAdmin === 'super_admin') {
        return next();
    }
    
    return res.apiError('Super administrator access required', 403);
};

// Middleware para verificar roles específicos
const hasRole = (...allowedRoles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.apiError('Authentication required', 401);
        }
        
        const userRole = req.user.rolTeacher || req.user.rolStudent || req.user.rolAdmin;
        
        if (!userRole || !allowedRoles.includes(userRole)) {
            return res.apiError(`Access denied. Required roles: ${allowedRoles.join(', ')}`, 403);
        }
        
        return next();
    };
};

// Middleware para verificar si el usuario puede acceder a un recurso específico
const canAccessResource = (resourceType, resourceIdParam = 'id') => {
    return async (req, res, next) => {
        if (!req.user) {
            return res.apiError('Authentication required', 401);
        }
        
        const resourceId = req.params[resourceIdParam];
        const userId = req.user.idTeacher || req.user.idEstudent || req.user.idAdministrator;
        const userRole = req.user.rolTeacher || req.user.rolStudent || req.user.rolAdmin;
        
        // Los administradores pueden acceder a cualquier recurso
        if (userRole && ['admin', 'super_admin', 'director'].includes(userRole)) {
            return next();
        }
        
        // Los usuarios solo pueden acceder a sus propios recursos
        if (resourceType === 'profile' || resourceType === 'user') {
            if (userId.toString() === resourceId) {
                return next();
            }
        }
        
        // Reglas específicas por tipo de recurso
        switch (resourceType) {
            case 'student':
                if (req.user.idEstudent && req.user.idEstudent.toString() === resourceId) {
                    return next();
                }
                break;
            case 'teacher':
                if (req.user.idTeacher && req.user.idTeacher.toString() === resourceId) {
                    return next();
                }
                break;
            case 'admin':
                if (req.user.idAdministrator && req.user.idAdministrator.toString() === resourceId) {
                    return next();
                }
                break;
        }
        
        return res.apiError('Access denied to this resource', 403);
    };
};

// Middleware para verificar permisos específicos de administrador
const hasAdminPermission = (permission) => {
    return async (req, res, next) => {
        if (!req.user) {
            return res.apiError('Authentication required', 401);
        }
        
        if (!req.user.rolAdmin) {
            return res.apiError('Administrator access required', 403);
        }
        
        // Super admins tienen todos los permisos
        if (req.user.rolAdmin === 'super_admin') {
            return next();
        }
        
        // Verificar permisos específicos
        try {
            const permissions = req.user.permissions || {};
            
            if (permissions[permission] === true) {
                return next();
            }
            
            return res.apiError(`Permission denied: ${permission}`, 403);
            
        } catch (error) {
            console.error('Permission check error:', error);
            return res.apiError('Permission verification failed', 500);
        }
    };
};

// Middleware para verificar estado del usuario
const isActiveUser = (req, res, next) => {
    if (!req.user) {
        return res.apiError('Authentication required', 401);
    }
    
    const userState = req.user.stateTeacher || req.user.stateEstudent || req.user.stateAdmin;
    
    if (userState !== 'active') {
        return res.apiError(`Account is ${userState}. Contact administrator.`, 403);
    }
    
    return next();
};

// Middleware para registrar actividad del usuario
const logUserActivity = (action = 'unknown') => {
    return (req, res, next) => {
        if (req.user) {
            const userId = req.user.idTeacher || req.user.idEstudent || req.user.idAdministrator;
            const userType = req.user.rolTeacher ? 'teacher' : 
                           req.user.rolStudent ? 'student' : 'admin';
            const username = req.user.usernameTeahcer || req.user.usernameEstudent || req.user.usernameAdmin;
            
            console.log(`User Activity - ${new Date().toISOString()} - User: ${username} (${userType}:${userId}) - Action: ${action} - IP: ${req.ip} - URL: ${req.originalUrl}`);
        }
        next();
    };
};

// Middleware combinado para verificaciones múltiples
const requireAuth = (options = {}) => {
    const {
        roles = [],
        permissions = [],
        activeOnly = true,
        logActivity = null
    } = options;
    
    return async (req, res, next) => {
        // Verificar autenticación
        if (!req.user) {
            return res.apiError('Authentication required', 401);
        }
        
        // Verificar estado activo
        if (activeOnly) {
            const userState = req.user.stateTeacher || req.user.stateEstudent || req.user.stateAdmin;
            if (userState !== 'active') {
                return res.apiError(`Account is ${userState}. Contact administrator.`, 403);
            }
        }
        
        // Verificar roles
        if (roles.length > 0) {
            const userRole = req.user.rolTeacher || req.user.rolStudent || req.user.rolAdmin;
            if (!userRole || !roles.includes(userRole)) {
                return res.apiError(`Access denied. Required roles: ${roles.join(', ')}`, 403);
            }
        }
        
        // Verificar permisos (solo para admins)
        if (permissions.length > 0 && req.user.rolAdmin) {
            const userPermissions = req.user.permissions || {};
            const hasPermission = permissions.some(perm => userPermissions[perm] === true) || req.user.rolAdmin === 'super_admin';
            
            if (!hasPermission) {
                return res.apiError(`Permission denied. Required: ${permissions.join(', ')}`, 403);
            }
        }
        
        // Registrar actividad
        if (logActivity) {
            const userId = req.user.idTeacher || req.user.idEstudent || req.user.idAdministrator;
            const userType = req.user.rolTeacher ? 'teacher' : req.user.rolStudent ? 'student' : 'admin';
            const username = req.user.usernameTeahcer || req.user.usernameEstudent || req.user.usernameAdmin;
            
            console.log(`User Activity - ${new Date().toISOString()} - User: ${username} (${userType}:${userId}) - Action: ${logActivity} - IP: ${req.ip} - URL: ${req.originalUrl}`);
        }
        
        return next();
    };
};

module.exports = {
    isAuthenticated,
    isStudent,
    isTeacher,
    isAdmin,
    isSuperAdmin,
    hasRole,
    canAccessResource,
    hasAdminPermission,
    isActiveUser,
    logUserActivity,
    requireAuth
};