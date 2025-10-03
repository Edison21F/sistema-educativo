const express = require("express");
const router = express.Router();

const {mostrarMensaje} = require('../controller/index.controller')

router.get('/', mostrarMensaje)

module.exports = router