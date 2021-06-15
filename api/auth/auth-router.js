const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require("bcryptjs");
const users = require("../users/users-model");
const jwt = require("jsonwebtoken");


router.post("/register", validateRoleName, (req, res, next) => {
  let user = req.body;
  
  const rounds = process.env.BCRY_ROUNDS || 8;
  let hash = bcrypt.hashSync(user.password, rounds);
  
  user.password = hash;
  users.add(user)
  .then(newUser => {
    res.status(201).json(newUser)
  })
  .catch(next);

});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  

  if(bcrypt.compareSync(req.body.password, req.user.password)){
    const token = buildToken(req.user);
    res.json({
      message:`${req.user.username} is back!`,
      token
    })
  }else{
    next({
      status:401,
      message: "Invalid credentials"
    });
  }
  
});
function buildToken(user){
  const payload = {
    subject: user.user_id,
    role_name: user.role_name,
    username: user.username
  }
  const options = {
    expiresIn: "1d",
  }
  return jwt.sign(payload, JWT_SECRET, options);
}

module.exports = router;
