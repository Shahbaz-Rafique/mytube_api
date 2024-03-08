const crypto = require('crypto');

const algorithm = 'sha512';

function hashPassword(password) {
    const hash = crypto.createHash(algorithm).update(password).digest('hex');
    return hash;
}

module.exports = {
    hashPassword,
};
