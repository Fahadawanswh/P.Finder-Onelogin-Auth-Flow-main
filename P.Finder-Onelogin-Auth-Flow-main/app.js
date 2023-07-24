require('dotenv').config();

var express = require('express');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session');

// Use Passport with OpenId Connect strategy to
// authenticate users with OneLogin
var passport = require('passport');
var OneLoginStrategy = require('passport-openidconnect').Strategy;

const baseUri = `${process.env.OIDC_BASE_URI}/oidc/2`;

// Configure the OpenId Connect Strategy
// with credentials obtained from OneLogin
passport.use(new OneLoginStrategy({
  issuer: baseUri,
  clientID: process.env.OIDC_CLIENT_ID,
  clientSecret: process.env.OIDC_CLIENT_SECRET,
  authorizationURL: `${baseUri}/auth`,
  userInfoURL: `${baseUri}/me`,
  tokenURL: `${baseUri}/token`,
  callbackURL: process.env.OIDC_REDIRECT_URI,
  passReqToCallback: true
},
  function (req, issuer, userId, profile, accessToken, refreshToken, params, cb) {

    // console.log('issuer:', issuer);
    // console.log('userId:', userId);
     console.log('accessToken:', accessToken);
    // console.log('refreshToken:', refreshToken);
    // console.log('params:', params);
    // console.log('id_token', params['id_token']);

    req.session.accessToken = accessToken;
    req.session.idToken = params['id_token'];

    return cb(null, profile);
  }));

passport.serializeUser(function (user, done) {
  done(null, user);
});

passport.deserializeUser(function (obj, done) {
  done(null, obj);
});

var app = express();

app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

// Passport requires session to persist the authentication
// so were using express-session for this example
app.use(session({
  secret: 'kLvVFANA2wgEgf',
  resave: false,
  saveUninitialized: true
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

app.get('/', function (req, res) {
  res.redirect('/login');
});

// Initiates an authentication request with OneLogin
// The user will be redirect to OneLogin and once authenticated
// they will be returned to the callback handler below
app.get('/login', passport.authenticate('openidconnect', {
  successReturnToOrRedirect: "/",
  scope: 'profile'
}));

// Callback handler that OneLogin will redirect back to
// after successfully authenticating the user
app.get('/oauth/callback', passport.authenticate('openidconnect', {
  callback: true,
  successReturnToOrRedirect: '/redirect',
  failureRedirect: '/'
}));

app.get('/redirect', function (req, res) {
  // console.log('req.session.idToken', req.session.idToken);
  let baseSuiteletUrl = process.env.SUITELET_URL;
  let suiteletUrl = baseSuiteletUrl + "&idt=" + req.session.idToken + "&at=" + req.session.accessToken;
  res.redirect(suiteletUrl);
});

app.get('/oauth/revoke', function (req, res) {
  let baseSuiteletUrl = process.env.SUITELET_URL;
  let suiteletUrl = baseSuiteletUrl + "&revokesession=true";
  res.redirect(suiteletUrl);
});

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

//

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

//comment

module.exports = app;
