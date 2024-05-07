const crypto = require('crypto');
const bcrypt = require('bcrypt');

const secret = crypto.randomBytes(64).toString('hex');
const hashedSecret = bcrypt.hashSync(secret, 10);

module.exports = {
  secret: secret,
  hashedSecret: hashedSecret
};