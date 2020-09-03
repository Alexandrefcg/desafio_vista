#!/usr/bin/env node

const express = require('express')
    , session = require('express-session')  // https://github.com/expressjs/session
    , bodyParser = require('body-parser')
    , cookieParser = require('cookie-parser')
    , MemoryStore = require('memorystore')(session) // https://github.com/roccomuso/memorystore
    , path = require('path')
    , DSAuthCodeGrant = require('./lib/DSAuthCodeGrant')
    , DsJwtAuth = require('./lib/DSJwtAuth')
    , passport = require('passport')
    , DocusignStrategy = require('passport-docusign')
    , docOptions = require('./config/documentOptions.json')
    , docNames = require('./config/documentNames.json')
    , dsConfig = require('./config/index.js').config
    , commonControllers = require('./lib/commonControllers')
    , flash = require('express-flash')
    , helmet = require('helmet') // https://expressjs.com/en/advanced/best-practice-security.html
    , moment = require('moment')
    , csrf = require('csurf') // https://www.npmjs.com/package/csurf
    , eg001 = require('./eg001EmbeddedSigning');

const PORT = process.env.PORT || 5000
    , HOST = process.env.HOST || 'localhost'
    , max_session_min = 180
    , csrfProtection = csrf({ cookie: true })
    ;

let hostUrl = 'http://' + HOST + ':' + PORT
if (dsConfig.appUrl != '' && dsConfig.appUrl != '{APP_URL}') {hostUrl = dsConfig.appUrl}

let app = express()
  .use(helmet())
  .use(express.static(path.join(__dirname, 'public')))
  .use(cookieParser())
  .use(session({
    secret: dsConfig.sessionSecret,
    name: 'ds-launcher-session',
    cookie: {maxAge: max_session_min * 60000},
    saveUninitialized: true,
    resave: true,
    store: new MemoryStore({
        checkPeriod: 86400000 // prune expired entries every 24h
  })}))
  .use(passport.initialize())
  .use(passport.session())
  .use(bodyParser.urlencoded({ extended: true }))
  .use(((req, res, next) => {
    res.locals.user = req.user;
    res.locals.session = req.session;
    res.locals.dsConfig = { ...dsConfig, docOptions: docOptions, docNames: docNames };
    res.locals.hostUrl = hostUrl; // Used by DSAuthCodeGrant#logout
    next()})) // Send user info to views
  .use(flash())
  .set('views', path.join(__dirname, 'views'))
  .set('view engine', 'ejs')
  // Add an instance of DSAuthCodeGrant to req
  .use((req, res, next) => {
      req.dsAuthCodeGrant = new DSAuthCodeGrant(req);
      req.dsAuthJwt = new DsJwtAuth(req);
      req.dsAuth = req.dsAuthCodeGrant;
      if(req.session.authMethod === 'jwt-auth') {
          req.dsAuth = req.dsAuthJwt;
      }
      next()
  })
  // Routes
  .get('/', commonControllers.indexController)
  .get('/ds/login', commonControllers.login)
  .get('/ds/callback', [dsLoginCB1, dsLoginCB2]) // OAuth callbacks. See below
  .get('/ds/logout', commonControllers.logout)
  .get('/ds/logoutCallback', commonControllers.logoutCallback)
  .get('/ds/mustAuthenticate', commonControllers.mustAuthenticateController)
  .get('/ds-return', commonControllers.returnController)
  .use(csrfProtection) // CSRF protection for the following routes
  .get('/eg001', eg001.getController)
  .post('/eg001', eg001.createController);

function dsLoginCB1 (req, res, next) {req.dsAuthCodeGrant.oauth_callback1(req, res, next)}
function dsLoginCB2 (req, res, next) {req.dsAuthCodeGrant.oauth_callback2(req, res, next)}

/* Start the web server */
if (dsConfig.dsClientId && dsConfig.dsClientId !== '{CLIENT_ID}' &&
    dsConfig.dsClientSecret && dsConfig.dsClientSecret !== '{CLIENT_SECRET}') {
    app.listen(PORT)
    console.log(`Listening on ${PORT}`);
    console.log(`Ready! Open ${hostUrl}`);
} else {
  console.log(`PROBLEM: You need to set the clientId (Integrator Key), and perhaps other settings as well. 
You can set them in the configuration file config/appsettings.json or set environment variables.\n`);
  process.exit();
}

passport.serializeUser  (function(user, done) {done(null, user)});
passport.deserializeUser(function(obj,  done) {done(null, obj)});

let docusignStrategy = new DocusignStrategy({
    production: dsConfig.production,
    clientID: dsConfig.dsClientId,
    clientSecret: dsConfig.dsClientSecret,
    callbackURL: hostUrl + '/ds/callback',
    state: true 
  },
  function _processDsResult(accessToken, refreshToken, params, profile, done) {    
    let user = profile;
    user.accessToken = accessToken;
    user.refreshToken = refreshToken;
    user.expiresIn = params.expires_in;
    user.tokenExpirationTimestamp = moment().add(user.expiresIn, 's'); 
    return done(null, user);
  }
);

if (!dsConfig.allowSilentAuthentication) {  
  docusignStrategy.authorizationParams = function(options) {
    return {prompt: 'login'};
  }
}
passport.use(docusignStrategy);
