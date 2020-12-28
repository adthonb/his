const express = require('express');
const app = express();
const mongo = require('mongoose');
const db = mongo.createConnection('mongodb://localhost/his_database');
const passport = require('passport');
const OAuth2Strategy = require('passport-oauth').OAuth2Strategy;
const { createLogger, format, transports } = require('winston');
const { combine, timestamp } = format;
const path = require('path');
const rateLimit = require("express-rate-limit");

// Configure the logger to write on file system
const logger = createLogger({
  level: 'info',
  format: combine(
    timestamp(),
  ),
  transports: [
    new transports.File({ filename: path.join('logs', 'error.log'), level: 'error' }),
    new transports.File({ filename: path.join('logs', 'combined.log') }),
  ],
});

// Configure schema for MongoDB database
const userSchema = new mongo.Schema({
  name: {
    first: String,
    last: String
  },
  email: {
    type: String,
    require: true,
    unique: true
  }
});

// OAuth 2.0 authorization from specified service provider
passport.use('provider', new OAuth2Strategy({
  authorizationURL: 'https://www.provider.com/oauth2/authorize',
  tokenURL: 'https://www.provider.com/oauth2/token',
  clientID: '123',
  clientSecret: 'secret',
  callbackURL: 'http://localhost:3000/auth/provider/callback'
}, (accessToken, refreshToken, profile, done) => {
  const User = db.model('User', userSchema);
  logger.info(`Email: ${profile.email}, Token: ${accessToken}, Refresh Token: ${refreshToken}`);
  User.findOneAndUpdate({
    email: profile.email,
    token: accessToken,
    refreshToken: refreshToken
  }, (err, user) => {
    if (err) {
      logger.error(`User not found, Error: ${err}`);
    }
    done(err, user);
  });
}
));

// Our API authorization
passport.use(new BearerStrategy(
  function(token, done) {
    User.findOne({ token: token }, function (err, user) {
      if (err) {
        return done(err);
      }
      if (!user) {
        return done(null, false);
      }
      return done(null, user, { scope: 'read' });
    });
  }
));

const loginLimiter = rateLimit({
  windowMs: 45 * 60 * 1000, // 45 mins window
  max: 15, // start blocking after 5 requests
  message:
    "Too many request login from this IP, please try again after 45 mins"
});

app.use(express.json());

app.get('/', (req, res) => {
  res.send('Hello World!')
})

// User log-in to service provider
app.get('/auth/provider', loginLimiter, passport.authenticate('provider'));

// OAuth 2.0 service provider callback
app.get('/auth/provider/callback', passport.authenticate('provider', { successRedirect: '/', failureRedirect: '/login' }));

// verify bearer token to accept API request
app.post('/profile', passport.authenticate('bearer', { session: false }), (req, res) => {
  logger.info('POST request with body: ' + JSON.stringify(req.body));
  res.status(200).json('Success POST request with body: ' + JSON.stringify(req.body));
});
  
app.listen(3000, () => {
  console.log(`App listening at http://localhost:${port}`);
});