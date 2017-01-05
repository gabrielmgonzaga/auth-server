// Authentication controller
const jwt = require('jwt-simple')
const User = require('../models/user')
const config = require('../config')

// Token Generator
function tokenForUser(user) {
  const timestamp = new Date().getTime()
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret)
}

// Login
exports.login = function(req, res, next) {
  res.send({ token: tokenForUser(req.user) })
}

// Signup
exports.signup = function(req, res, next) {
  const email = req.body.email
  const password = req.body.password

  // Email/password validation
  if (!email || !password) {
    return res.status(422).send({ error: 'You must provide email and password' })
  }

  // See if user with given email exists
  User.findOne({ email: email }, function(err, existingUser) {
    // If connection to DB fails
    if (err) return next(err)

    // If email exists, return error
    if (existingUser) return res.status(422).send({ error: 'Email is in use' })

    // If email doesn't exist, create and save user
    const user = new User({
      email: email,
      password: password
    })

    user.save(function(err) {
      if (err) return next(err)

      // Generate token for user if successful
      res.json({ token: tokenForUser(user) })
    })
  })
}
