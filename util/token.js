const jwt = require('jsonwebtoken')

const createAccessToken = (user) => {
    return jwt.sign(user, process.env.TOKEN_SECRET, {expiresIn: '1d'}) // 1 day tokens expire
};

module.exports = { createAccessToken }