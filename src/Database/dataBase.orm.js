const { Sequelize } = require("sequelize");
const { MYSQLHOST, MYSQLUSER, MYSQLPASSWORD, MYSQLDATABASE, MYSQLPORT, MYSQL_URI } = require("../keys");

let sequelize;

// Usar URI de conexión si está disponible
if (MYSQL_URI) {
    sequelize = new Sequelize(MYSQL_URI, {
        dialect: 'mysql',
        dialectOptions: {
            charset: 'utf8mb4', // Soporte para caracteres especiales
        },
        pool: {
            max: 20, // Número máximo de conexiones
            min: 5,  // Número mínimo de conexiones
            acquire: 30000, // Tiempo máximo en ms para obtener una conexión
            idle: 10000 // Tiempo máximo en ms que una conexión puede estar inactiva
        },
        logging: false // Desactiva el logging para mejorar el rendimiento
    });
} else {
    // Configuración para parámetros individuales
    sequelize = new Sequelize(MYSQLDATABASE, MYSQLUSER, MYSQLPASSWORD, {
        host: MYSQLHOST,
        port: MYSQLPORT,
        dialect: 'mysql',
        dialectOptions: {
            charset: 'utf8mb4', // Soporte para caracteres especiales
        },
        pool: {
            max: 20, // Número máximo de conexiones
            min: 5,  // Número mínimo de conexiones
            acquire: 30000, // Tiempo máximo en ms para obtener una conexión
            idle: 10000 // Tiempo máximo en ms que una conexión puede estar inactiva
        },
        logging: false // Desactiva el logging para mejorar el rendimiento
    });
}

// Autenticar y sincronizar
sequelize.authenticate()
    .then(() => {
        console.log("Conexión establecida con la base de datos");
    })
    .catch((err) => {
        console.error("No se pudo conectar a la base de datos:", err.message);
    });

// Sincronización de la base de datos
const syncOptions = process.env.NODE_ENV === 'development' ? { force: true } : { alter: true };

sequelize.sync(syncOptions)
    .then(() => {
        console.log('Base de Datos sincronizadas');
    })
    .catch((error) => {
        console.error('Error al sincronizar la Base de Datos:', error);
    });

//extracionModelos
const usuarioModel = require('../models/sql/usuario')
const rolModel = require('../models/sql/rol')
const detalleRolModel = require('../models/sql/detalleRol')
const pageModel = require('../models/sql/page')
const teacherModel = require('../models/sql/teacher')
const studentModel = require('../models/sql/student')
const administratorModel = require('../models/sql/administrator')

//intaciar los modelos a sincronizar
const usuario = usuarioModel(sequelize, Sequelize)
const rol = rolModel(sequelize, Sequelize)
const detalleRol = detalleRolModel(sequelize, Sequelize)
const page = pageModel(sequelize, Sequelize)
const teacher = teacherModel(sequelize, Sequelize)
const student = studentModel(sequelize, Sequelize)
const administrator = administratorModel(sequelize, Sequelize)

//relaciones o foreingKeys

usuario.hasMany(detalleRol)
detalleRol.belongsTo(usuario)

rol.hasMany(detalleRol)
detalleRol.belongsTo(rol)

usuario.hasMany(page)
page.belongsTo(usuario)

// Relaciones para el sistema de autenticación
// Los maestros pueden tener múltiples páginas asignadas
teacher.hasMany(page, { foreignKey: 'teacherId' })
page.belongsTo(teacher, { foreignKey: 'teacherId' })

// Los estudiantes pueden tener múltiples páginas asignadas
student.hasMany(page, { foreignKey: 'studentId' })
page.belongsTo(student, { foreignKey: 'studentId' })

// Los administradores pueden gestionar múltiples páginas
administrator.hasMany(page, { foreignKey: 'administratorId' })
page.belongsTo(administrator, { foreignKey: 'administratorId' })

// Relaciones entre usuarios y roles
teacher.hasMany(detalleRol, { foreignKey: 'teacherId' })
detalleRol.belongsTo(teacher, { foreignKey: 'teacherId' })

student.hasMany(detalleRol, { foreignKey: 'studentId' })
detalleRol.belongsTo(student, { foreignKey: 'studentId' })

administrator.hasMany(detalleRol, { foreignKey: 'administratorId' })
detalleRol.belongsTo(administrator, { foreignKey: 'administratorId' })

// Exportar el objeto sequelize
module.exports = {
  usuario,
  rol,
  detalleRol,
  page,
  teacher,
  student,
  administrator
};