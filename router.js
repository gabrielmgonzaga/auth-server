// Routes
const Authentication = require('./controllers/authentication')
const passportService = require('./services/passport')
const passport = require('passport')

const requireAuth = passport.authenticate('jwt', { session: false })
const requireLogIn = passport.authenticate('local', { session: false })

module.exports = function(app) {
  app.get('/', requireAuth, function(req, res) {
    res.send({ success: true })
  })
  app.post('/login', requireLogIn, Authentication.login)
  app.post('/signup', Authentication.signup)
}
