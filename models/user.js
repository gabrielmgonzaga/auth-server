// DB user model
const mongoose = require('mongoose')
const Schema = mongoose.Schema
const bcrypt = require('bcrypt-nodejs')

// Model
const userSchema = new Schema({
  email: { type: String, unique: true, lowercase: true },
  password: String
})

// Before saving model, encrypt the password.
userSchema.pre('save', function(next) {
  // get access to the user model
  const user = this

  // Salt generator
  bcrypt.genSalt(10, function(err, salt) {
    if (err) return next(err)

    // Encrypt the password using Salt
    bcrypt.hash(user.password, salt, null, function(err, hash) {
      if (err) return next(err)

      // Overwrite plain text password with encrypted password
      user.password = hash
      next()
    })
  })
})

// Searches DB to compare password during login
userSchema.methods.comparePassword = function(candidatePassword, callback) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if (err) return callback(err)

    callback(null, isMatch)
  })
}

// Create model class
const ModelClass = mongoose.model('user', userSchema)

module.exports = ModelClass
