const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const FormData = require('form-data');
const { 
    cifrarDatos, 
    descifrarDatos, 
    hashPassword, 
    verifyPassword,
    cifrarCampos,
    descifrarCampos,
    sanitizarEntrada,
    validarDatos 
} = require('./encrypDates');

//archvios de coneccion
const orm = require('../Database/dataBase.orm');
const sql = require('../Database/dataBase.sql');
const mongo = require('../Database/dataBaseMongose')


const guardarYSubirArchivo = async (archivo, filePath, columnName, idEstudent, url, req) => {
    const validaciones = {
        imagen: [".PNG", ".JPG", ".JPEG", ".GIF", ".TIF", ".png", ".jpg", ".jpeg", ".gif", ".tif", ".ico", ".ICO", ".webp", ".WEBP"],
        pdf: [".pdf", ".PDF"]
    };
    const tipoArchivo = columnName === 'photoEstudent' ? 'imagen' : 'pdf';
    const validacion = path.extname(archivo.name);

    if (!validaciones[tipoArchivo].includes(validacion)) {
        throw new Error('Archivo no compatible.');
    }

    return new Promise((resolve, reject) => {
        archivo.mv(filePath, async (err) => {
            if (err) {
                return reject(new Error('Error al guardar el archivo.'));
            } else {
                try {
                    await sql.promise().query(`UPDATE students SET ${columnName} = ? WHERE idEstudent = ?`, [archivo.name, idEstudent]);

                    const formData = new FormData();
                    formData.append('image', fs.createReadStream(filePath), {
                        filename: archivo.name,
                        contentType: archivo.mimetype,
                    });

                    const response = await axios.post(url, formData, {
                        headers: {
                            'Content-Type': 'multipart/form-data',
                            'X-CSRF-Token': req.csrfToken(),
                            'Cookie': req.headers.cookie
                        },
                    });

                    if (response.status !== 200) {
                        throw new Error('Error al subir archivo al servidor externo.');
                    }

                    resolve();
                } catch (uploadError) {
                    console.error('Error al subir archivo al servidor externo:', uploadError.message);
                    reject(new Error('Error al subir archivo al servidor externo.'));
                }
            }
        });
    });
};

// ==================== TEACHER STRATEGIES ====================

passport.use(
    'local.teacherSignin',
    new LocalStrategy(
        {
            usernameField: 'username',
            passwordField: 'password',
            passReqToCallback: true,
        },
        async (req, username, password, done) => {
            try {
                // Sanitizar entrada
                const sanitizedUsername = sanitizarEntrada(username);

                // Buscar teacher en la base de datos
                const teacher = await orm.teacher.findOne({
                    where: { usernameTeahcer: sanitizedUsername }
                });

                if (!teacher) {
                    return done(null, false, req.flash("message", "El nombre de usuario no existe."));
                }

                // Verificar contraseña con bcrypt
                const isPasswordValid = await verifyPassword(password, teacher.passwordTeacher);
                if (!isPasswordValid) {
                    return done(null, false, req.flash("message", "Contraseña incorrecta."));
                }

                // Verificar estado del teacher
                if (teacher.stateTeacher !== 'active') {
                    return done(null, false, req.flash("message", `Cuenta ${teacher.stateTeacher}. Contacte al administrador.`));
                }

                // Descifrar nombre para mensaje de bienvenida
                const decryptedName = descifrarDatos(teacher.completeNmeTeacher);
                return done(null, teacher, req.flash("success", `Bienvenido ${decryptedName}`));

            } catch (error) {
                console.error('Teacher signin error:', error);
                return done(error);
            }
        }
    )
);

passport.use(
    'local.studentSignin',
    new LocalStrategy(
        {
            usernameField: 'username',
            passwordField: 'password',
            passReqToCallback: true,
        },
        async (req, username, password, done) => {
            try {
                // Sanitizar entrada
                const sanitizedUsername = sanitizarEntrada(username);

                // Buscar student en la base de datos
                const student = await orm.student.findOne({
                    where: { usernameEstudent: sanitizedUsername }
                });

                if (!student) {
                    return done(null, false, req.flash("message", "El nombre de usuario no existe."));
                }

                // Verificar contraseña con bcrypt
                const isPasswordValid = await verifyPassword(password, student.passwordEstudent);
                if (!isPasswordValid) {
                    return done(null, false, req.flash("message", "Contraseña incorrecta."));
                }

                // Verificar estado del student
                if (student.stateEstudent !== 'active') {
                    return done(null, false, req.flash("message", `Cuenta ${student.stateEstudent}. Contacte al administrador.`));
                }

                // Descifrar nombre para mensaje de bienvenida
                const decryptedName = descifrarDatos(student.completeNameEstudent);
                return done(null, student, req.flash("success", `Bienvenido ${decryptedName}`));

            } catch (error) {
                console.error('Student signin error:', error);
                return done(error);
            }
        }
    )
);

// ==================== ADMINISTRATOR SIGNIN ====================

passport.use(
    'local.adminSignin',
    new LocalStrategy(
        {
            usernameField: 'username',
            passwordField: 'password',
            passReqToCallback: true,
        },
        async (req, username, password, done) => {
            try {
                // Sanitizar entrada
                const sanitizedUsername = sanitizarEntrada(username);

                // Buscar administrator en la base de datos
                const admin = await orm.administrator.findOne({
                    where: { usernameAdmin: sanitizedUsername }
                });

                if (!admin) {
                    return done(null, false, req.flash("message", "El nombre de usuario no existe."));
                }

                // Verificar si la cuenta está bloqueada
                if (admin.lockUntil && admin.lockUntil > new Date()) {
                    const minutesLeft = Math.ceil((admin.lockUntil - new Date()) / (1000 * 60));
                    return done(null, false, req.flash("message", `Cuenta bloqueada. Intente en ${minutesLeft} minutos.`));
                }

                // Verificar contraseña con bcrypt
                const isPasswordValid = await verifyPassword(password, admin.passwordAdmin);
                if (!isPasswordValid) {
                    // Incrementar intentos fallidos
                    const loginAttempts = (admin.loginAttempts || 0) + 1;
                    let updateData = { loginAttempts };

                    // Bloquear cuenta después de 5 intentos fallidos
                    if (loginAttempts >= 5) {
                        updateData.lockUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutos
                        updateData.loginAttempts = 0; // Reset counter
                    }

                    await orm.administrator.update(updateData, {
                        where: { idAdministrator: admin.idAdministrator }
                    });

                    return done(null, false, req.flash("message", "Contraseña incorrecta."));
                }

                // Verificar estado del administrador
                if (admin.stateAdmin !== 'active') {
                    return done(null, false, req.flash("message", `Cuenta ${admin.stateAdmin}. Contacte al administrador principal.`));
                }

                // Reset intentos fallidos y actualizar último login
                await orm.administrator.update({
                    loginAttempts: 0,
                    lockUntil: null,
                    lastLogin: new Date()
                }, {
                    where: { idAdministrator: admin.idAdministrator }
                });

                // Descifrar nombre para mensaje de bienvenida
                const decryptedName = descifrarDatos(admin.completeNameAdmin);
                return done(null, admin, req.flash("success", `Bienvenido ${decryptedName}`));

            } catch (error) {
                console.error('Admin signin error:', error);
                return done(error);
            }
        }
    )
);

// ==================== SIGNUP STRATEGIES ====================

passport.use(
    'local.studentSignup',
    new LocalStrategy(
        {
            usernameField: 'username',
            passwordField: 'password',
            passReqToCallback: true,
        },
        async (req, username, password, done) => {
            try {
                // Sanitizar entrada
                const sanitizedUsername = sanitizarEntrada(username);

                // Verificar si el usuario ya existe
                const existingUser = await orm.student.findOne({ 
                    where: { usernameEstudent: sanitizedUsername } 
                });

                if (existingUser) {
                    return done(null, false, req.flash('message', 'El nombre de usuario ya existe.'));
                }

                const {
                    identificationCard,
                    completeNameEstudent,
                    emailEstudent,
                    celularEstudent,
                    ubicacion,
                    grade,
                    guardianName,
                    guardianPhone
                } = req.body;

                // Validar datos requeridos
                if (!identificationCard || !completeNameEstudent || !emailEstudent || !celularEstudent) {
                    return done(null, false, req.flash('message', 'Todos los campos obligatorios deben completarse.'));
                }

                // Validar longitud de datos antes del cifrado
                if (!validarDatos(identificationCard) || !validarDatos(completeNameEstudent) || 
                    !validarDatos(emailEstudent) || !validarDatos(celularEstudent)) {
                    return done(null, false, req.flash('message', 'Los datos exceden la longitud permitida.'));
                }

                // Hash de la contraseña
                const hashedPassword = await hashPassword(password);

                // Preparar datos del nuevo estudiante
                let newStudent = {
                    identificationCardStudent: cifrarDatos(sanitizarEntrada(identificationCard)),
                    completeNameEstudent: cifrarDatos(sanitizarEntrada(completeNameEstudent)),
                    emailEstudent: cifrarDatos(sanitizarEntrada(emailEstudent)),
                    celularEstudent: cifrarDatos(sanitizarEntrada(celularEstudent)),
                    usernameEstudent: sanitizedUsername,
                    passwordEstudent: hashedPassword,
                    ubicationStudent: sanitizarEntrada(ubicacion) || '',
                    grade: sanitizarEntrada(grade) || '',
                    guardianName: guardianName ? cifrarDatos(sanitizarEntrada(guardianName)) : null,
                    guardianPhone: guardianPhone ? cifrarDatos(sanitizarEntrada(guardianPhone)) : null,
                    rolStudent: 'student',
                    stateEstudent: 'pending',
                    enrollmentDate: new Date(),
                    createStudent: new Date().toLocaleString()
                };

                // Guardar estudiante
                const savedStudent = await orm.student.create(newStudent);

                // Manejar subida de archivo si existe
                if (req.files && req.files.photoEstudent) {
                    const { photoEstudent } = req.files;
                    try {
                        const photoFilePath = path.join(__dirname, '/../public/img/usuario/', photoEstudent.name);
                        await guardarYSubirArchivo(photoEstudent, photoFilePath, 'photoEstudent', savedStudent.idEstudent, 'https://www.central.profego-edu.com/imagenEstudiante', req);
                    } catch (fileError) {
                        console.error('Error uploading student photo:', fileError);
                        // No fallar registro por error de archivo
                    }
                }

                return done(null, savedStudent);

            } catch (error) {
                console.error('Student signup error:', error);
                return done(error);
            }
        }
    )
);

passport.use(
    'local.teacherSignup',
    new LocalStrategy(
        {
            usernameField: 'username',
            passwordField: 'password',
            passReqToCallback: true,
        },
        async (req, username, password, done) => {
            try {
                // Sanitizar entrada
                const sanitizedUsername = sanitizarEntrada(username);

                // Verificar si el usuario ya existe
                const existingUser = await orm.teacher.findOne({ 
                    where: { usernameTeahcer: sanitizedUsername } 
                });

                if (existingUser) {
                    return done(null, false, req.flash('message', 'El nombre de usuario ya existe.'));
                }

                const {
                    identificationCard,
                    completeNmeTeacher,
                    emailTeacher,
                    phoneTeacher,
                    specialization,
                    experience
                } = req.body;

                // Validar datos requeridos
                if (!identificationCard || !completeNmeTeacher || !emailTeacher || !phoneTeacher) {
                    return done(null, false, req.flash('message', 'Todos los campos obligatorios deben completarse.'));
                }

                // Validar longitud de datos antes del cifrado
                if (!validarDatos(identificationCard) || !validarDatos(completeNmeTeacher) || 
                    !validarDatos(emailTeacher) || !validarDatos(phoneTeacher)) {
                    return done(null, false, req.flash('message', 'Los datos exceden la longitud permitida.'));
                }

                // Hash de la contraseña
                const hashedPassword = await hashPassword(password);

                // Preparar datos del nuevo teacher
                let newTeacher = {
                    identificationCardTeacher: cifrarDatos(sanitizarEntrada(identificationCard)),
                    completeNmeTeacher: cifrarDatos(sanitizarEntrada(completeNmeTeacher)),
                    emailTeacher: cifrarDatos(sanitizarEntrada(emailTeacher)),
                    phoneTeacher: cifrarDatos(sanitizarEntrada(phoneTeacher)),
                    usernameTeahcer: sanitizedUsername,
                    passwordTeacher: hashedPassword,
                    specialization: sanitizarEntrada(specialization) || '',
                    experience: parseInt(experience) || 0,
                    rolTeacher: 'teacher',
                    stateTeacher: 'pending',
                    createTeahcer: new Date().toLocaleString()
                };

                // Guardar teacher
                const savedTeacher = await orm.teacher.create(newTeacher);

                // Manejar subida de archivo si existe
                if (req.files && req.files.photoTeacher) {
                    const { photoTeacher } = req.files;
                    try {
                        const photoFilePath = path.join(__dirname, '/../public/img/usuario/', photoTeacher.name);
                        await guardarYSubirArchivo(photoTeacher, photoFilePath, 'photoEstudent', savedTeacher.idTeacher, 'https://www.central.profego-edu.com/imagenTeacher', req);
                    } catch (fileError) {
                        console.error('Error uploading teacher photo:', fileError);
                        // No fallar registro por error de archivo
                    }
                }

                return done(null, savedTeacher);

            } catch (error) {
                console.error('Teacher signup error:', error);
                return done(error);
            }
        }
    )
);

// ==================== ADMINISTRATOR SIGNUP ====================

passport.use(
    'local.adminSignup',
    new LocalStrategy(
        {
            usernameField: 'username',
            passwordField: 'password',
            passReqToCallback: true,
        },
        async (req, username, password, done) => {
            try {
                // Solo super admins pueden crear nuevos admins
                if (!req.user || req.user.rolAdmin !== 'super_admin') {
                    return done(null, false, req.flash('message', 'No tienes permisos para crear administradores.'));
                }

                // Sanitizar entrada
                const sanitizedUsername = sanitizarEntrada(username);

                // Verificar si el usuario ya existe
                const existingUser = await orm.administrator.findOne({ 
                    where: { usernameAdmin: sanitizedUsername } 
                });

                if (existingUser) {
                    return done(null, false, req.flash('message', 'El nombre de usuario ya existe.'));
                }

                const {
                    identificationCard,
                    completeNameAdmin,
                    emailAdmin,
                    phoneAdmin,
                    department,
                    rolAdmin,
                    permissions
                } = req.body;

                // Validar datos requeridos
                if (!identificationCard || !completeNameAdmin || !emailAdmin || !phoneAdmin) {
                    return done(null, false, req.flash('message', 'Todos los campos obligatorios deben completarse.'));
                }

                // Validar longitud de datos antes del cifrado
                if (!validarDatos(identificationCard) || !validarDatos(completeNameAdmin) || 
                    !validarDatos(emailAdmin) || !validarDatos(phoneAdmin)) {
                    return done(null, false, req.flash('message', 'Los datos exceden la longitud permitida.'));
                }

                // Hash de la contraseña
                const hashedPassword = await hashPassword(password);

                // Preparar datos del nuevo administrador
                let newAdmin = {
                    identificationCardAdmin: cifrarDatos(sanitizarEntrada(identificationCard)),
                    completeNameAdmin: cifrarDatos(sanitizarEntrada(completeNameAdmin)),
                    emailAdmin: cifrarDatos(sanitizarEntrada(emailAdmin)),
                    phoneAdmin: cifrarDatos(sanitizarEntrada(phoneAdmin)),
                    usernameAdmin: sanitizedUsername,
                    passwordAdmin: hashedPassword,
                    department: sanitizarEntrada(department) || '',
                    rolAdmin: rolAdmin || 'admin',
                    permissions: permissions || {},
                    stateAdmin: 'active', // Admins creados por super admin se activan automáticamente
                    loginAttempts: 0,
                    createAdmin: new Date().toLocaleString()
                };

                // Guardar administrador
                const savedAdmin = await orm.administrator.create(newAdmin);

                return done(null, savedAdmin);

            } catch (error) {
                console.error('Admin signup error:', error);
                return done(error);
            }
        }
    )
);

// ==================== SERIALIZATION ====================

passport.serializeUser((user, done) => {
    // Determinar tipo de usuario y guardar información mínima
    let userInfo = {};
    
    if (user.idTeacher) {
        userInfo = {
            id: user.idTeacher,
            type: 'teacher',
            username: user.usernameTeahcer
        };
    } else if (user.idEstudent) {
        userInfo = {
            id: user.idEstudent,
            type: 'student',
            username: user.usernameEstudent
        };
    } else if (user.idAdministrator) {
        userInfo = {
            id: user.idAdministrator,
            type: 'admin',
            username: user.usernameAdmin
        };
    }
    
    done(null, userInfo);
});

passport.deserializeUser(async (userInfo, done) => {
    try {
        let user = null;
        
        switch (userInfo.type) {
            case 'teacher':
                user = await orm.teacher.findByPk(userInfo.id);
                break;
            case 'student':
                user = await orm.student.findByPk(userInfo.id);
                break;
            case 'admin':
                user = await orm.administrator.findByPk(userInfo.id);
                break;
            default:
                return done(new Error('Invalid user type'));
        }
        
        if (!user) {
            return done(new Error('User not found'));
        }
        
        done(null, user);
    } catch (error) {
        console.error('Deserialize user error:', error);
        done(error);
    }
});

module.exports = passport;