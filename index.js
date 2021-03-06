const express = require('express')
const http = require('http')
const bodyParser = require('body-parser')
const morgan = require('morgan')
const app = express()
const router = require('./router')
const mongoose = require('mongoose')

// DB hook
mongoose.connect('mongodb://localhost:auth/auth')

// App setup
app.use(morgan('combined'))
app.use(bodyParser.json({ type: '*/*' }))
router(app)

// Server setup
const port = process.env.PORT || 8080
const server = http.createServer(app)
server.listen(port)
console.log(`listening on ${port}`)
