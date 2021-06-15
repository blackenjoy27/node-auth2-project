// jsonwebtoken
const jwt = require('jsonwebtoken')

const { JWT_SECRET } = require("../secrets");

module.exports = function (user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role: user.user_role,
  }
  const options = {
    expiresIn: '1d',
  }
  return jwt.sign(
    payload,
    JWT_SECRET,
    options,
  )
}
