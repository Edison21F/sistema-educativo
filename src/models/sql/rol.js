const rol = (sequelize, type) =>{
    return sequelize.define('roles', {
        idRol: {
            type: type.INTEGER,
            autoIncrement: true,
            primaryKey: true,
        },
        nameRol: type.STRING,
        descriptionRol: type.STRING,
        stateRol: type.STRING,
        createRol: type.STRING,
        updateRol: type.STRING,
    }, {
        timestamps: false,
        comment: 'Tabla de Roles'
    })
}

module.exports = rol;