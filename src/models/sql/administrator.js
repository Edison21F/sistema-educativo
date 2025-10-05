const administrator = (sequelize, type) => {
    return sequelize.define('administrators', {
        idAdministrator: {
            type: type.INTEGER,
            autoIncrement: true,
            primaryKey: true,
        },
        identificationCardAdmin: {
            type: type.TEXT,
            allowNull: false,
            unique: true,
            comment: 'Encrypted identification card'
        },
        completeNameAdmin: {
            type: type.TEXT,
            allowNull: false,
            comment: 'Encrypted full name'
        },
        emailAdmin: {
            type: type.TEXT,
            allowNull: false,
            comment: 'Encrypted email address'
        },
        phoneAdmin: {
            type: type.TEXT,
            allowNull: false,
            comment: 'Encrypted phone number'
        },
        usernameAdmin: {
            type: type.STRING(100),
            allowNull: false,
            unique: true,
            comment: 'Plain text username for login'
        },
        passwordAdmin: {
            type: type.STRING(255),
            allowNull: false,
            comment: 'Hashed password'
        },
        photoAdmin: {
            type: type.STRING(255),
            allowNull: true,
            comment: 'Profile photo filename'
        },
        rolAdmin: {
            type: type.ENUM('admin', 'super_admin', 'director', 'coordinator'),
            defaultValue: 'admin',
            comment: 'Administrator role'
        },
        stateAdmin: {
            type: type.ENUM('active', 'inactive', 'pending', 'suspended'),
            defaultValue: 'pending',
            comment: 'Account status'
        },
        permissions: {
            type: type.JSON,
            allowNull: true,
            comment: 'Admin permissions object'
        },
        department: {
            type: type.STRING(100),
            allowNull: true,
            comment: 'Administrative department'
        },
        lastLogin: {
            type: type.DATE,
            allowNull: true,
            comment: 'Last login timestamp'
        },
        loginAttempts: {
            type: type.INTEGER,
            defaultValue: 0,
            comment: 'Failed login attempts counter'
        },
        lockUntil: {
            type: type.DATE,
            allowNull: true,
            comment: 'Account lock expiry time'
        },
        createAdmin: {
            type: type.STRING(50),
            allowNull: false,
            comment: 'Creation timestamp'
        },
        updateAdmin: {
            type: type.STRING(50),
            allowNull: true,
            comment: 'Last update timestamp'
        }
    }, {
        timestamps: false,
        tableName: 'administrators',
        comment: 'Administrators table with encrypted sensitive data'
    });
};

module.exports = administrator;