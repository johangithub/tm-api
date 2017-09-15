// =======================
// get the packages we need ============
// =======================
var express     = require('express')
var path        = require('path')
var app         = express()
var bodyParser  = require('body-parser')
var morgan      = require('morgan')
var helmet = require('helmet')
const sqlite3 = require('sqlite3').verbose()
var jwt    = require('jsonwebtoken') // used to create, sign, and verify tokens
var config = require('./config') // get our config file
var bcrypt = require('bcrypt')
var cors = require('cors')

// =======================
// configuration =========
// =======================
var port = process.env.PORT || 5005 // used to create, sign, and verify tokens
let db = new sqlite3.Database(config.database)
app.set('jwtSecret', config.jwtSecret) // secret variable

//CORS
//Requests are only allowed from whitelisted url
var whitelist = ['http://localhost:8080']
var corsOptions = {
    origin: function (origin, callback){
        // whitelist-test pass
        if (whitelist.indexOf(origin) !== -1){
            callback(null, true)
        }
        // whitelist-test fail
        else{
            callback(new Error('Not on whitelist'))    
        }
    }
}
app.use(cors(corsOptions))

// helmet protects the application with various functions
app.use(helmet())

// use body parser so we can get info from POST and/or URL parameters
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())

// use morgan to log requests to the console
app.use(morgan('dev'))

// =======================
// routes ================
// =======================
// basic route

app.get('/', function(req, res) {
    res.send('Hello! The API is at http://localhost:' + port + '/api')
})

// API ROUTES -------------------
var apiRoutes = express.Router()

//The middleware is not applied here, because we cannot apply token-requiring
//middleware when they first login and authenticate
apiRoutes.post('/authenticate', function(req, res){
    let email = req.body.email
    var password = req.body.password
    var sqlget = `SELECT email as email, salt as salt, hash as hash, role as role, id as id
                  from user where email=(?)`
    db.get(sqlget, [email], (err, user)=>{
        if (err){
            throw err
        }
        else if (!user){
            res.json({
                success: false,
                message: 'Authentication failed. User not found.'
            })      
        }
        else if (user){
            bcrypt.compare(password, user.hash, function(err, confirmed){
                if (!confirmed){ // password don't match
                    res.json({
                        success: false, 
                        message: 'Authentication failed. Wrong password.' 
                    })
                }
                else if (confirmed){
                    var token = jwt.sign({email: user.email, role: user.role, id: user.id}, app.get('jwtSecret'), {
                        expiresIn: 60*60*24 // expires in 24 hours
                    })

                    // return the information including token as JSON
                    res.json({
                      success: true,
                      message: 'Enjoy your token!',
                      token: token
                    })
                }
            })

        }
    })
})

//route middleware to verify a token
apiRoutes.use(function(req, res, next){
    var token = req.body.token || req.query.token || req.headers['x-access-token'] || req.headers.authorization
    if (token){
        jwt.verify(token, app.get('jwtSecret'), function(err, decoded){
            if (err){
                return res.status(403).send({
                    success: false,
                    message: 'Failed to authenticate token.' })  
            }
            else {
                req.decoded = decoded
                next()
            }
        })
    }
    else{
        return res.status(403).send({
            success: false,
            message: 'No token provided'
        })
    }
})

//route middleware to verify authority
apiRoutes.use(function(req, res, next){

    //offciers/officerId only accessible by admin
    var role = req.decoded.role
    var path = req.path
    console.log(role, path)
    if (role=='admin' || role =='peon'){
        next()
    }
    //Without proper role
    else{
        console.log('Failed')
        res.status(403)
        res.json({
            success: false,
            message: 'Forbidden'
        })
    }
})

apiRoutes.get('/', function(req, res){
    res.json({message: 'Welcome to the API ROOT'})
})

apiRoutes.get('/users', function(req, res){
    var requesterEmail = req.decoded.email
    var users = []
    let sql1 = 'SELECT email as email, role as role from user where email = ?' 
    db.all(sql1, requesterEmail, (err, rows) =>{
        if(err){
            throw err
        }
        else if (!rows){
            res.json({
                success: false,
                message: 'User not found'
            })
        }
        else{
            rows.forEach((row)=>{
                users.push(row)
            })
            res.json({
                success: true,
                data: users
            }
            )
        }
    })
})

apiRoutes.get('/officers/:officerId', function(req, res){
    var sqlget = `SELECT ? as officerId`
    var officerId = req.params.officerId
    db.get(sqlget, [officerId], (err, row)=>{
        if (err){
            throw err
        }
        else if (!row){
            res.json({
                success: false,
                message: 'Officer not found.'
            })     
        }
        else {
            res.json({
                success: true,
                officerId: row.officerId
            })
        }
    })
})

apiRoutes.get('/billets/:billetId', function(req, res){
    res.json({
        success: true,
        billetId: req.params.billetId
    })
})

app.use('/api', apiRoutes)

// =======================
// start the server ======
// =======================
app.listen(port, '0.0.0.0')
console.log('Magic happens at http://localhost:' + port)