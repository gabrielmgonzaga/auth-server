// Passport Service
const passport = require('passport')
const User = require('../models/user')
const config = require('../config')
const JwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt
const LocalStrategy = require('passport-local')

// Local Strategy for Login
const localOptions = { usernameField: 'email' }
const localLogin = new LocalStrategy(localOptions, function(email, password, done) {
  // Verify email & password
  User.findOne({ email: email }, function(err, user) {
    if (err) return done(err)
    if (!user) return done(null, false) // user was not found

    // Compare passwords
    user.comparePassword(password, function(err, isMatch) {
      if (err) return done(err)
      if (!isMatch) return done(null, false)

      return done(null, user)
    })
  })
})

// JWT Strategy
const jwtOptions = {
  // Extracts token from authorization
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
}

const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
  // See if user ID in payload exists in DB.
  User.findById(payload.sub, function(err, user) {
    if (err) return done(err, false)

    return (user) ? done(null, user) : done(null, false)
  })
})

passport.use(jwtLogin)
passport.use(localLogin)
