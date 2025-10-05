const CryptoJS = require('crypto-js');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');

dotenv.config();

const claveSecreta = process.env.CLAVE_SECRETA || 'cifrarDatos';
const saltRounds = parseInt(process.env.SALT_ROUNDS) || 12;

// Función para cifrar datos sensibles
function cifrarDatos(datos) {
    try {
        if (datos === null || datos === undefined || datos === '') {
            return datos;
        }
        const cifrado = CryptoJS.AES.encrypt(JSON.stringify(datos), claveSecreta).toString();
        return cifrado;
    } catch (error) {
        console.error('Error al cifrar datos:', error.message);
        throw new Error('Failed to encrypt data');
    }
}

// Función para descifrar datos sensibles
function descifrarDatos(cifrado) {
    try {
        if (cifrado === null || cifrado === undefined || cifrado === '') {
            return cifrado;
        }
        const bytes = CryptoJS.AES.decrypt(cifrado, claveSecreta);
        const datos = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
        return datos;
    } catch (error) {
        console.error('Error al descifrar datos:', error.message);
        throw new Error('Failed to decrypt data');
    }
}

// Función para hashear contraseñas
async function hashPassword(password) {
    try {
        if (!password || password.trim() === '') {
            throw new Error('Password cannot be empty');
        }
        const hashedPassword = await bcrypt.hash(password.trim(), saltRounds);
        return hashedPassword;
    } catch (error) {
        console.error('Error al hashear contraseña:', error.message);
        throw new Error('Failed to hash password');
    }
}

// Función para verificar contraseñas
async function verifyPassword(password, hashedPassword) {
    try {
        if (!password || !hashedPassword) {
            return false;
        }
        const isValid = await bcrypt.compare(password.trim(), hashedPassword);
        return isValid;
    } catch (error) {
        console.error('Error al verificar contraseña:', error.message);
        return false;
    }
}

// Función para cifrar múltiples campos de un objeto
function cifrarCampos(objeto, campos) {
    try {
        const objetoCifrado = { ...objeto };
        campos.forEach(campo => {
            if (objetoCifrado[campo] !== undefined && objetoCifrado[campo] !== null) {
                objetoCifrado[campo] = cifrarDatos(objetoCifrado[campo]);
            }
        });
        return objetoCifrado;
    } catch (error) {
        console.error('Error al cifrar campos:', error.message);
        throw new Error('Failed to encrypt fields');
    }
}

// Función para descifrar múltiples campos de un objeto
function descifrarCampos(objeto, campos) {
    try {
        const objetoDescifrado = { ...objeto };
        campos.forEach(campo => {
            if (objetoDescifrado[campo] !== undefined && objetoDescifrado[campo] !== null) {
                objetoDescifrado[campo] = descifrarDatos(objetoDescifrado[campo]);
            }
        });
        return objetoDescifrado;
    } catch (error) {
        console.error('Error al descifrar campos:', error.message);
        throw new Error('Failed to decrypt fields');
    }
}

// Función para validar datos antes del cifrado
function validarDatos(datos) {
    if (typeof datos === 'object' && datos !== null) {
        return JSON.stringify(datos).length <= 1000; // Límite de longitud
    }
    return typeof datos === 'string' && datos.length <= 500;
}

// Función para sanitizar entrada de usuario
function sanitizarEntrada(entrada) {
    if (typeof entrada !== 'string') {
        return entrada;
    }
    
    // Remover caracteres potencialmente peligrosos
    return entrada
        .replace(/[<>]/g, '') // Remover < y >
        .replace(/javascript:/gi, '') // Remover javascript:
        .replace(/on\w+=/gi, '') // Remover manejadores de eventos
        .trim();
}

module.exports = {
    cifrarDatos,
    descifrarDatos,
    hashPassword,
    verifyPassword,
    cifrarCampos,
    descifrarCampos,
    validarDatos,
    sanitizarEntrada
}