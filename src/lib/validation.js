const { body, validationResult } = require('express-validator');
const { sanitizarEntrada } = require('./encrypDates');

// ==================== COMMON VALIDATION RULES ====================

const usernameValidation = body('username')
    .notEmpty()
    .withMessage('Username is required')
    .isLength({ min: 3, max: 50 })
    .withMessage('Username must be between 3 and 50 characters')
    .matches(/^[a-zA-Z0-9_.-]+$/)
    .withMessage('Username can only contain letters, numbers, dots, hyphens and underscores')
    .customSanitizer(value => sanitizarEntrada(value));

const passwordValidation = body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number');

const emailValidation = (fieldName) => body(fieldName)
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail()
    .customSanitizer(value => sanitizarEntrada(value));

const phoneValidation = (fieldName) => body(fieldName)
    .matches(/^\+?[1-9]\d{1,14}$/)
    .withMessage('Please provide a valid phone number')
    .customSanitizer(value => sanitizarEntrada(value));

const nameValidation = (fieldName) => body(fieldName)
    .notEmpty()
    .withMessage(`${fieldName} is required`)
    .isLength({ min: 2, max: 100 })
    .withMessage(`${fieldName} must be between 2 and 100 characters`)
    .matches(/^[a-zA-ZÀ-ÿ\s]+$/)
    .withMessage(`${fieldName} can only contain letters and spaces`)
    .customSanitizer(value => sanitizarEntrada(value));

const identificationValidation = body('identificationCard')
    .notEmpty()
    .withMessage('Identification card is required')
    .isLength({ min: 5, max: 20 })
    .withMessage('Identification card must be between 5 and 20 characters')
    .customSanitizer(value => sanitizarEntrada(value));

// ==================== SPECIFIC VALIDATION SETS ====================

const loginValidationRules = [
    usernameValidation,
    body('password')
        .notEmpty()
        .withMessage('Password is required')
        .isLength({ min: 6 })
        .withMessage('Password must be at least 6 characters long'),
    body('userType')
        .isIn(['teacher', 'student', 'admin'])
        .withMessage('User type must be teacher, student, or admin')
];

const studentRegistrationValidation = [
    usernameValidation,
    passwordValidation,
    identificationValidation,
    nameValidation('completeNameEstudent'),
    emailValidation('emailEstudent'),
    phoneValidation('celularEstudent'),
    body('ubicacion')
        .optional()
        .isLength({ max: 255 })
        .withMessage('Location must not exceed 255 characters')
        .customSanitizer(value => sanitizarEntrada(value)),
    body('grade')
        .optional()
        .isLength({ max: 20 })
        .withMessage('Grade must not exceed 20 characters')
        .customSanitizer(value => sanitizarEntrada(value)),
    body('guardianName')
        .optional()
        .isLength({ min: 2, max: 100 })
        .withMessage('Guardian name must be between 2 and 100 characters')
        .matches(/^[a-zA-ZÀ-ÿ\s]*$/)
        .withMessage('Guardian name can only contain letters and spaces')
        .customSanitizer(value => sanitizarEntrada(value)),
    body('guardianPhone')
        .optional()
        .matches(/^\+?[1-9]\d{1,14}$/)
        .withMessage('Please provide a valid guardian phone number')
        .customSanitizer(value => sanitizarEntrada(value))
];

const teacherRegistrationValidation = [
    usernameValidation,
    passwordValidation,
    identificationValidation,
    nameValidation('completeNmeTeacher'),
    emailValidation('emailTeacher'),
    phoneValidation('phoneTeacher'),
    body('specialization')
        .optional()
        .isLength({ max: 255 })
        .withMessage('Specialization must not exceed 255 characters')
        .customSanitizer(value => sanitizarEntrada(value)),
    body('experience')
        .optional()
        .isInt({ min: 0, max: 50 })
        .withMessage('Experience must be a number between 0 and 50')
];

const adminRegistrationValidation = [
    usernameValidation,
    passwordValidation,
    identificationValidation,
    nameValidation('completeNameAdmin'),
    emailValidation('emailAdmin'),
    phoneValidation('phoneAdmin'),
    body('department')
        .optional()
        .isLength({ max: 100 })
        .withMessage('Department must not exceed 100 characters')
        .customSanitizer(value => sanitizarEntrada(value)),
    body('rolAdmin')
        .optional()
        .isIn(['admin', 'super_admin', 'director', 'coordinator'])
        .withMessage('Invalid admin role'),
    body('permissions')
        .optional()
        .isObject()
        .withMessage('Permissions must be an object')
];

const profileUpdateValidation = [
    body('completeNmeTeacher')
        .optional()
        .isLength({ min: 2, max: 100 })
        .withMessage('Teacher name must be between 2 and 100 characters')
        .matches(/^[a-zA-ZÀ-ÿ\s]*$/)
        .withMessage('Teacher name can only contain letters and spaces')
        .customSanitizer(value => sanitizarEntrada(value)),
    body('completeNameEstudent')
        .optional()
        .isLength({ min: 2, max: 100 })
        .withMessage('Student name must be between 2 and 100 characters')
        .matches(/^[a-zA-ZÀ-ÿ\s]*$/)
        .withMessage('Student name can only contain letters and spaces')
        .customSanitizer(value => sanitizarEntrada(value)),
    body('completeNameAdmin')
        .optional()
        .isLength({ min: 2, max: 100 })
        .withMessage('Admin name must be between 2 and 100 characters')
        .matches(/^[a-zA-ZÀ-ÿ\s]*$/)
        .withMessage('Admin name can only contain letters and spaces')
        .customSanitizer(value => sanitizarEntrada(value)),
    body('emailTeacher')
        .optional()
        .isEmail()
        .withMessage('Please provide a valid teacher email address')
        .normalizeEmail()
        .customSanitizer(value => sanitizarEntrada(value)),
    body('emailEstudent')
        .optional()
        .isEmail()
        .withMessage('Please provide a valid student email address')
        .normalizeEmail()
        .customSanitizer(value => sanitizarEntrada(value)),
    body('emailAdmin')
        .optional()
        .isEmail()
        .withMessage('Please provide a valid admin email address')
        .normalizeEmail()
        .customSanitizer(value => sanitizarEntrada(value)),
    body('phoneTeacher')
        .optional()
        .matches(/^\+?[1-9]\d{1,14}$/)
        .withMessage('Please provide a valid teacher phone number')
        .customSanitizer(value => sanitizarEntrada(value)),
    body('celularEstudent')
        .optional()
        .matches(/^\+?[1-9]\d{1,14}$/)
        .withMessage('Please provide a valid student phone number')
        .customSanitizer(value => sanitizarEntrada(value)),
    body('phoneAdmin')
        .optional()
        .matches(/^\+?[1-9]\d{1,14}$/)
        .withMessage('Please provide a valid admin phone number')
        .customSanitizer(value => sanitizarEntrada(value)),
    body('specialization')
        .optional()
        .isLength({ max: 255 })
        .withMessage('Specialization must not exceed 255 characters')
        .customSanitizer(value => sanitizarEntrada(value)),
    body('experience')
        .optional()
        .isInt({ min: 0, max: 50 })
        .withMessage('Experience must be a number between 0 and 50'),
    body('ubicationStudent')
        .optional()
        .isLength({ max: 255 })
        .withMessage('Location must not exceed 255 characters')
        .customSanitizer(value => sanitizarEntrada(value)),
    body('grade')
        .optional()
        .isLength({ max: 20 })
        .withMessage('Grade must not exceed 20 characters')
        .customSanitizer(value => sanitizarEntrada(value)),
    body('guardianName')
        .optional()
        .isLength({ min: 2, max: 100 })
        .withMessage('Guardian name must be between 2 and 100 characters')
        .matches(/^[a-zA-ZÀ-ÿ\s]*$/)
        .withMessage('Guardian name can only contain letters and spaces')
        .customSanitizer(value => sanitizarEntrada(value)),
    body('guardianPhone')
        .optional()
        .matches(/^\+?[1-9]\d{1,14}$/)
        .withMessage('Please provide a valid guardian phone number')
        .customSanitizer(value => sanitizarEntrada(value)),
    body('department')
        .optional()
        .isLength({ max: 100 })
        .withMessage('Department must not exceed 100 characters')
        .customSanitizer(value => sanitizarEntrada(value))
];

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

// ==================== MIDDLEWARE FUNCTION ====================

const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.apiError('Validation errors', 400, errors.array());
    }
    next();
};

// ==================== RATE LIMITING VALIDATION ====================

const createRateLimitValidation = (windowMs = 15 * 60 * 1000, maxAttempts = 5) => {
    const attempts = new Map();
    
    return (req, res, next) => {
        const key = req.ip + (req.body.username || '');
        const now = Date.now();
        const windowStart = now - windowMs;
        
        // Limpiar intentos antiguos
        if (attempts.has(key)) {
            attempts.set(key, attempts.get(key).filter(attempt => attempt > windowStart));
        }
        
        const userAttempts = attempts.get(key) || [];
        
        if (userAttempts.length >= maxAttempts) {
            return res.apiError('Too many login attempts. Try again later.', 429);
        }
        
        // Agregar intento actual
        userAttempts.push(now);
        attempts.set(key, userAttempts);
        
        next();
    };
};

module.exports = {
    loginValidationRules,
    studentRegistrationValidation,
    teacherRegistrationValidation,
    adminRegistrationValidation,
    profileUpdateValidation,
    changePasswordValidation,
    handleValidationErrors,
    createRateLimitValidation
};