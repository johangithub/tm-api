// =======================
// get the packages we need ============
// =======================
var express     = require('express')
var http        = require('http')
var https       = require('https')
var fs          = require('fs')
var path        = require('path')
var app         = express()
var bodyParser  = require('body-parser')
var morgan      = require('morgan')
var helmet      = require('helmet')
const sqlite3   = require('sqlite3').verbose()
var jwt         = require('jsonwebtoken') // used to create, sign, and verify tokens
var config      = require('./config') // get our config file
var bcrypt      = require('bcrypt')
var cors        = require('cors')
var moment      = require('moment')

// =======================
// configuration =========
// =======================
var port = process.env.PORT || 5005 // used to create, sign, and verify tokens
let db = new sqlite3.Database(config.database)
app.set('jwtSecret', config.jwtSecret) // secret variable

//CORS
//Requests are only allowed from whitelisted url
// var whitelist = ['http://localhost:8080','https://localhost:8080']
var corsOptions = {
    origin: function (origin, callback){
        // whitelist-test pass
        if (true){//(whitelist.indexOf(origin) !== -1){
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

app.get('/', (req, res)=> {
    res.send('Hello! The API is at http://localhost:' + port + '/api')
})

// API ROUTES -------------------
var apiRoutes = express.Router()

// Login Attempt Limit middleware
var failCallback = function (req, res, next, nextValidRequestDate) {
    res.status(404).send({
        success: false,
        message: 'Too Many Login Attempts. Please try again '+moment(nextValidRequestDate).fromNow()
    }) // brute force protection triggered, send them back to the login page
}
var handleStoreError = function (error) {
    log.error(error) // log this error so we can figure out what went wrong
    // cause node to exit, hopefully restarting the process fixes the problem
    throw {
        message: error.message,
        parent: error.parent
    }
}

var ExpressBrute = require('express-brute')
var store = new ExpressBrute.MemoryStore()
var userBruteForce = new ExpressBrute(store, {
    freeRetries: 1000, // How many incorrect attempts before locking
    minWait: 1*60*1000, //5 minutes,
    maxWait: 2*60*1000, //1 hour,
    failCallback: failCallback,
    handleStoreError: handleStoreError
})

//The middleware is not applied here, because we cannot apply token-requiring
//middleware when they first login and authenticate
apiRoutes.post('/authenticate', 
    userBruteForce.getMiddleware({
    key: function(req, res, next){
        next(req.body.email)
    }}),
    (req, res)=>{
    let email = req.body.email
    var password = req.body.password
    var sqlget = `SELECT email as email, salt as salt, hash as hash, role as role, id as id
                  from user where email=(?)`
    db.get(sqlget, [email], (err, user)=>{
        //If error
        if (err){
            throw err
        }
        //If user not found
        else if (!user){
            res.status(404).send({
                success: false,
                message: 'Authentication failed. User not found.'
            })      
        }
        //If user found
        else if (user){
            bcrypt.compare(password, user.hash, function(err, confirmed){
                if (!confirmed){ // password don't match
                    res.status(401).json({
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

    var role = req.decoded.role
    var path = req.path

    //temporary route blocking
//     if (role=='admin'){
//         next()
//     }
//     else if (role=='officer' && (path=='/billet_view' || path == '/officers')){
//         next()
//     }
//     else if (role=='billet_owner' && (path=='/officer_view' || path == '/billets')){
//         next()
//     }
//     else if (role=='losing_commander' && path=='/officers'){
    if (role){
        next()
    }
    //Without proper role
    else{
        res.status(403)
        res.json({
            success: false,
            message: 'Forbidden'
        })
    }
})

apiRoutes.get('/', (req, res)=>{
    res.json({message: 'Welcome to the API ROOT'})
})

apiRoutes.get('/users', (req, res)=>{
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


//API End point for billet overview
apiRoutes.get('/billet_view', (req, res)=>{
    var sqlget = `SELECT     
    CAST(AFPCID as INT) as id,
    position_AFSC_Core as afsc,
    RPI as api,
    AJJ as location,
    Unit as unit,
    Authorized_Rank as grade,    
    case conus when 1 then 'CONUS' else 'OCONUS' end as conus,
    RDTM as aircraft,
    case length(AEW) when 2 then AEW else 'NONE' end as state,
    GeneralDutyTitle as general_duty_title,
    ActualDutyTitle as actual_duty_title,
    Description as description,
    mandatory_quals as quals,
    PRD_Remarks as prd_remarks,
    MAJCOM as majcom,
    position as position,
    pas as pas 
                         from billets`
        db.all(sqlget, [], function(err, rows){
        try{
        var data = []
        rows.forEach((row)=>{
            data.push(handleBuffer(row))
        })
        res.json({
          success: true,
          data: data
        })
        }
        catch(err){
            console.log(err)
        }
    })
})

apiRoutes.get('/ao_dashboard_view', (req, res)=>{
    var sqlget = `SELECT * from officers`
    db.all(sqlget, [], (err, rows)=>{
        if (err){
            throw err
        }
        else {
            var outData = []
            rows.forEach((row)=>{
                temp={}
                data = handleBuffer(row)
                temp['dod_id'] = data['ID']
                temp['general'] = general_data_parse(data)
                temp['language'] = language_data_parse(data)
                temp['projected'] = projection_data_parse(data)
                temp['duty'] = duty_data_parse(data)
                temp['asgn_code'] = asgn_code_parse(data)
                temp['service_dates'] = service_dates_parse(data)
                temp['rated'] = rated_data_parse(data)
                temp['courses'] = course_data_parse(data)
                temp['adsc'] = adsc_data_parse(data)
                temp['degree'] = degree_data_parse(data)
                temp['pme'] = pme_data_parse(data)
                temp['joint'] = joint_data_parse(data)
                temp['special_experience'] = special_experience_parse(data)
                temp['vml'] = Math.random() > .5 ? true : false
                outData.push(temp)
            })
            
            res.json({
                success: true,
                data: outData
            })
        }
    })
})

//API End point for overview of officers
apiRoutes.get('/officer_view', (req, res)=>{
    var sqlget = `SELECT rtg, flt_hrs_total, grade, rdtm, adjYG, id from officers`
    //rtg, flt_hrs_total, grade, rdtm, adjYG, id
    db.all(sqlget, [], (err, rows)=>{
        try{
        var data = []
        rows.forEach((row)=>{
            data.push(handleBuffer(row))
        })
	    res.json({
		  success: true,
		  data: data
	    })
        }
        catch(err){
            console.log(err)
        }
    })
})

function handleBuffer(row){
    var temp={}
    for (d in row){
        if(row[d] != null && typeof(row[d]) == 'object'){
            temp[d] = row[d].toString('utf-8')
        } else if (row[d] != null){
            temp[d] = row[d]
        }
    }
    return temp
}

//API endpoint for officers submitting ranked billets
apiRoutes.post('/officers', (req, res)=>{
    var officerId = req.decoded.id
    var comment = req.body.comment
    var departureDate = req.body.desiredDepartureDate
    var desiredRNLTD = req.body.desiredRNLTD
    var interests = req.body.interests
    var qualifications = req.body.qualifications
    var sqlPost = `UPDATE officers set comment = (?), 
                                   departureDate = (?), 
                                   desiredRNLTD = (?), 
                                   interests = (?), 
                                   qualifications = (?) 
                                       where rowid = (?)`
    db.run(sqlPost, [comment, departureDate, desiredRNLTD, interests, qualifications, officerId], function(err){
        //If error
        if (err){
            throw err
        }
        //If success 
        else {
            //changes property used for confirming update or delete statements
            console.log("Rows changed: " + this.changes)
            res.status(200).send({
                success: true,
                message: 'Successfully submitted.'
            })
        }
    })
})

//API endpoint for officers getting ranked billets

//API endpoint for officers submitting ranked billets
apiRoutes.post('/billets_fave', (req, res)=>{
    var officerId = req.decoded.id
    var rankedBillets = req.body.rankedBillets
    var sqlPost = 'UPDATE officers set rankedBillets = (?) where rowid = (?)' 
    db.run(sqlPost, [rankedBillets, officerId], (err)=>{
        //If error
        if (err){
            throw err
        }
        //If success 
        else {
            //changes property used for confirming update or delete statements
            console.log("Rows changed: " + this.changes)
            res.status(200).send({
                success: true,
                message: 'Successfully submitted.'
            })
        }
    })
})


//API endpoint for My Profile 
apiRoutes.get('/officers', (req, res)=>{
    var rowid = req.decoded.id 
    var sqlget = `SELECT * from officers where rowid = (?)`
    db.get(sqlget, [rowid], (err, row)=>{
        if (err){
            throw err
        }
        else {
            data = handleBuffer(row)
            outData = {}
            outData['language'] = language_data_parse(data)
            outData['general'] = general_data_parse(data)
            outData['projected'] = projection_data_parse(data)
            outData['duty'] = duty_data_parse(data)
            outData['asgn_code'] = asgn_code_parse(data)
            outData['service_dates'] = service_dates_parse(data)
            outData['rated'] = rated_data_parse(data)
            outData['courses'] = course_data_parse(data)
            outData['adsc'] = adsc_data_parse(data)
            outData['degree'] = degree_data_parse(data)
            outData['pme'] = pme_data_parse(data)
            outData['joint'] = joint_data_parse(data)
            outData['special_experience'] = special_experience_parse(data)
            outData.rowid = rowid
            res.json({
                success: true,
                data: outData
            })
        }
    })
})

//API endpoint for my billets page
apiRoutes.get('/billets/:billetId', (req, res)=>{
    res.json({
        success: true,
        billetId: req.params.billetId
    })
})

app.use('/api', apiRoutes)

// =======================
// start the server ======
// =======================


app.listen(port)
// const options = {
//   key: fs.readFileSync('../tm/localhost.key'),
//   cert: fs.readFileSync('../tm/localhost.crt'),
//   passphrase: '1234'
// };

// https.createServer(options, app).listen(port);
// console.log('Server up at https://localhost:' + port)

console.log('Server up at http://localhost:' + port)

function general_data_parse(data){
    general_data = {}
    general_data['firstName'] = data['firstName']
    general_data['lastName'] = data['lastName']
    general_data['proj_grade'] = data['grade_proj']
    general_data['grade'] = data['grade']
    general_data['adjYG'] = data['adjYG']
    general_data['tos'] = data['TOS']
    general_data['tis'] = data['TAFMS']
    general_data['component'] = data['component_t']
    general_data['func_cat'] = data['func_cat']
    general_data['comp_cat'] = data['comp_cat']
    general_data['record_status'] = data['record_status']
    general_data['accounting_status'] = data['accounting_status']
    general_data['posn'] = data['position_number']
    general_data['aef'] = data['aef']
    general_data['aef_start_date'] = formatSASDate(data['aef_start_Date'])
    general_data['aef_stop_date'] = formatSASDate(data['aef_stop_Date'])
    general_data['short_tour_num'] = data['short_tour_nbr'] ? data['short_tour_nbr'].trim() : 0 

    
    return general_data
}

function projection_data_parse(data){
    proj_data = {}
    proj_asgn = {}
    proj_asgn['pas'] = data['pas_proj']
    proj_asgn['afsc'] = data['afsc_selected']
    proj_asgn['asd'] = formatSASDate(data['asd'])
    proj_asgn['pdd'] = formatSASDate(data['pdd'])
    proj_asgn['rnltd'] = formatSASDate(data['rnltd'])

                    
    proj_duty = {}
    proj_duty['eff_date'] = formatSASDate(data['duty_status_proj_eff_date'])
    proj_duty['exp_date'] = formatSASDate(data['duty_status_proj_exp_date'])
    proj_duty['status'] = data['duty_status_proj']
    proj_duty['title_pending'] = data['duty_title_pending']
    proj_duty['cmd_lvl_pending'] = data['cmd_lvl_pending']
    proj_duty['afsc_pending'] = data['dafsc_pending']
    proj_duty['eff_date_pending'] = formatSASDate(data['duty_eff_date_pending'])
                            
    proj_course = []
    var i = 1
    while (data['projected_training_'+i]){
        course_temp = {}
        course_temp['course'] = data['projected_training_'+i]
        course_temp['course_ct'] = data['projected_training_ct_'+i]
        course_temp['start_date'] = formatSASDate(data['projected_training_start_date_'+i])
        course_temp['grad_date'] = formatSASDate(data['projected_training_grad_date_'+i])
        proj_course.push(course_temp)
        i += 1   
    }

    proj_data['assignment'] = proj_asgn
    proj_data['course'] = proj_course
    proj_data['duty'] = proj_duty

    return proj_data
}
function duty_data_parse(data){
    var duty_data = {}
    var duty_history = []
    for (let i=1;i<25;i++){
        var temp = {}
        if (data['hist_unit_'+i] || data['duty_hist_loc_'+i]){
        // If orgnum exists, trim
        data['hist_org_num_'+i] ? temp['org_num'] = data['hist_org_num_'+i].trim() : null
        temp['org_type'] = data['hist_org_type_'+i]
        temp['org_level'] = data['hist_org_level_'+i]
        temp['org_det'] = data['hist_org_det_'+i]
        temp['org_majcom'] = data['hist_majcom_'+i]
        temp['unit'] = data['hist_unit_'+i]
        temp['duty_title'] = data['duty_hist_title_'+i]
        temp['dafsc'] = data['duty_hist_dafsc_'+i]
        temp['location'] = data['duty_hist_loc_'+i]
        temp['country_state'] = data['duty_hist_cntryst_'+i]
        temp['command_level'] = data['duty_hist_cmd_lvl_'+i]
        temp['eff_date'] = formatSASDate(data['duty_hist_eff_date_'+i])
        duty_history.push(temp)
        }
    }

    var duty_exp = []
    var i = 1
    for (let i =1; i<=15;i++){
        exp_temp = {}
        exp_temp['duty_title'] = data['exp_duty_afs_title_'+i]
        exp_temp['duty_years'] = Math.round(data['exp_duty_calc_yrs_in_afs_'+i] * 10 ) / 10
        if (exp_temp['duty_title']){
            duty_exp.push(exp_temp)
        }
    }

    duty_data['status'] = data['duty_status']
    duty_data['status_ct'] = data['duty_status_ct']
    duty_data['title'] = data['duty_title']
    duty_data['dafsc'] = data['afsc_duty']
    duty_data['afsc_1'] = data['afsc_1']
    duty_data['afsc_2'] = data['afsc_2']
    duty_data['afsc_3'] = data['afsc_3']
    duty_data['unit'] = data['org_unit']
    duty_data['location'] = data['AJJ']
    duty_data['org_num'] = data['org_num']
    duty_data['org_type'] = data['org_type']    
    duty_data['org_level'] = data['org_level']
    duty_data['org_det'] = data['org_det']
    duty_data['pas'] = data['pas']
    duty_data['core_group'] = data['core_derived_group']
    duty_data['status_expire_date'] = formatSASDate(data['duty_status_exp_date'])                  
    duty_data['history'] = duty_history
    duty_data['experience'] = duty_exp
    return duty_data
}

function service_dates_parse(data){
    var service_dates = {}
    service_dates_column = ['das', 'ddlds', 'duty_status_eff_date', 'odsd', 'strd', 'dos', 'ead', 'pay_date', 'tafcsd',
    'tfcsd', 'grade_eff_date', 'dor', 'tafmsd', 'deros', 'cc_date', 'retsep_eff_date_proj']
    for (let i=0;i<service_dates_column.length;i++){
        service_dates[service_dates_column[i]] = formatSASDate(data[service_dates_column[i]])
    }
    return service_dates
}

function rated_data_parse(data){
    var rated_data = {}
    rated_data['aero_rating'] = data['aero_rating']
    rated_data['aero_rating_ct'] = data['aero_rating_ct']
    rated_data['flt_activity_code'] = data['flt_activity_code']
    rated_data['gates_curr'] = data['gates_curr']
    rated_data['flt_hrs_combat'] = data['flt_hrs_combat']
    rated_data['flt_hrs_instr'] = data['flt_hrs_instr']
    rated_data['flt_hrs_total'] = data['flt_hrs_total']
    rated_data['avn_service_code'] = data['avn_service_code']
    rated_data['avn_service_code_ct'] = data['avn_service_code_ct']
    rated_data['rdtm'] = data['rdtm']
    rated_data['aircrew_position_id'] = data['aircrew_position_id']
    rated_data['acp_status'] = data['acp_status']
    rated_data['acp_status_ct'] = data['acp_status_ct']
    rated_data['avn_service_date'] = formatSASDate(data['avn_service_date'])
    rated_data['acp_elig_date'] = formatSASDate(data['acp_elig_date'])
    rated_data['acp_effective_date'] = formatSASDate(data['acp_effective_date'])
    rated_data['acp_stop_date'] = formatSASDate(data['acp_stop_date'])
    rated_data['aero_rating_date'] = formatSASDate(data['aero_rating_date'])
    rated_data['return_to_fly_date'] = formatSASDate(data['return_to_fly_date'])

                                                                            
    aircraft_history = []
    var i = 1
    while (data['acft_hist_'+i]){
        acft_temp = {}
        acft_temp['aircraft'] = data['acft_hist_'+i]
        acft_temp['aircraft_date_flown'] = formatSASDate(data['acft_hist_date_flown_'+i])
        acft_temp['hours'] = Math.round(data['acft_hist_hrs_'+i] * 10 ) / 10
        aircraft_history.push(acft_temp)
                                i += 1
    }
    rated_data['aircraft_history'] = aircraft_history
    return rated_data
}

function degree_data_parse(data){
    var degree_data = {}
    var i = 1
    var degree_hist = []
    while (data['acad_spec_'+i]){
        var degree_temp = {}
        degree_temp['degree'] = data['acad_spec_'+i]
        degree_temp['degree_ct'] = data['acad_spec_ct_'+i]
        degree_temp['level'] = data['acad_educ_level_'+i]
        degree_temp['method'] = data['acad_educ_meth_'+i]
        degree_temp['school'] = data['acad_educ_inst_'+i]
        degree_temp['date'] = formatSASDate(data['acad_educ_date_'+i])
        degree_hist.push(degree_temp)
        i += 1
    }

    degree_data['history'] = degree_hist
    degree_data['highest'] = data['acad_edu_level_high']
    return degree_data
}

function course_data_parse(data){
    var course_data = []
    var i = 1
    while (data['course_'+i]){
        course_temp = {}
        course_temp['course'] = data['course_'+i]
        course_temp['date'] = formatSASDate(data['course_date_'+i])
                        course_data.push(course_temp)
        i+=1
    }
    return course_data
}

function pme_data_parse(data){
    var pme_data = {}
    var i = 1
    var pme_hist = []
    while (data['pme_'+i]){
        var pme_temp = {}
        pme_temp['course'] = data['pme_'+i]
        pme_temp['date'] = formatSASDate(data['pme_date_'+i])
        pme_temp['method'] = data['pme_method_'+i]
        pme_temp['level'] = data['pme_level_'+i]
                                delete data['pme_level_'+i] 
        pme_hist.push(pme_temp)
        i+=1
    }
    pme_data['history'] = pme_hist
    pme_data['pme_highest'] = data['pme_highest']
    return pme_data
}

function joint_data_parse(data){
    var joint_data = {}
    var joint_hist = []
    var i = 1
    while (data['jda_start_date_'+i]){
        joint_temp = {}
        joint_temp['start_date'] = formatSASDate(data['jda_start_date_'+i])
        joint_temp['stop_date'] = formatSASDate(data['jda_stop_date_'+i])
        joint_temp['type'] = data['jda_tour_type_'+i]
        joint_temp['credit'] = data['jda_tour_credit_'+i]
        joint_temp['reason'] = data['jda_completion_rsn_'+i]
        joint_temp['posn'] = data['jdamis_posn_number_'+i]
        joint_hist.push(joint_temp)
        i += 1
    }
    joint_data['history'] = joint_hist
    joint_data['jso_code'] = data['jso_spec_code']
    joint_data['jda_flag'] = data['jda_flag']
    joint_data['jso_jsonum_status'] = data['jso_jsonum_status'] 
    return joint_data

}

function adsc_data_parse(data){
    var adsc_data = []
    var i = 1
    while (data['adsc_'+i]){
        var adsc_temp = {}
        adsc_temp['adsc'] = data['adsc_'+i]
        adsc_temp['date'] = formatSASDate(data['adsc_date_'+i])
        adsc_data.push(adsc_temp)
        i += 1
    }
    return adsc_data
}

function special_experience_parse(data){
    var spec_exp = {}
    var nei_list = []
    var i = 1
    while (data['nei_'+i]){
        nei_temp = {}
        nei_temp['nei'] = data['nei_'+i]
        nei_temp['start_date'] = formatSASDate(data['nei_start_date_'+i])
        nei_temp['stop_date'] = formatSASDate(data['nei_stop_date_'+i])
        nei_list.push(nei_temp)
        i += 1
    }

    var i = 1
    var sei_list = []
    while (data['sei_gen_'+i]){
        sei_temp = {}
        sei_temp['sei'] = data['sei_gen_'+i]
        sei_list.push(sei_temp)
        i += 1
    }

    spec_exp['sei_duty'] = data['sei_duty']
    spec_exp['nuclear'] = nei_list
    spec_exp['sei'] = sei_list
    
    var acq_data = {}
    acq_data['career_level'] = data['auth_acq_career_lvl']
    acq_data['posn_cat'] = data['auth_acq_posn_cat']
    acq_data['posn_type'] = data['auth_acq_posn_type']
    spec_exp['acquisitions'] = acq_data
    
    spec_exp['WIC'] = data['WIC']
    return spec_exp
}

function language_data_parse(data){
    var lang_data = {}
    var lang_list = []
    for (let i=1;i<=5;i++){
        var lang_temp = {}
        lang_temp['id'] = data['lang_id_'+i]
        lang_temp['listen'] = data['lang_listen_comp_'+i]
        lang_temp['read'] = data['lang_read_comp_'+i]
        lang_temp['date'] = formatSASDate(data['lang_test_date_'+i])
                                                if (lang_temp['id']){
            lang_list.push(lang_temp)
        }
    }
    lang_data['list'] = lang_list 
    lang_data['dlab_score'] = Number(data['lang_dlab_score'])
    lang_data['dlab_date'] = formatSASDate(data['lang_dlab_date'])
    return lang_data
}

function asgn_code_parse(data){
    var asgn_data = {}
    var i = 1
    var abc_list = []
    while (data['abc_date_'+i]){
        var abc_temp={}
        abc_temp['date'] = formatSASDate(data['abc_date_'+i])
        abc_temp['code'] = data['abc_'+i]
        abc_list.push(abc_temp)
        i+=1
    }

    var i = 1
    var aac_list = []
    while (data['aac_date_'+i]){
        var aac_temp={}
        aac_temp['date'] = formatSASDate(data['aac_date_'+i])
        aac_temp['code'] = data['aac_'+i]
        aac_list.push(aac_temp)
        i+=1
    }

    var i = 1
    var alc_list = []
    while (data['alc_date_'+i]){
        var alc_temp={}
        alc_temp['date'] = formatSASDate(data['alc_date_'+i])
        alc_temp['code'] = data['alc_'+i]
        alc_list.push(alc_temp)
        i+=1
    }

    asgn_data['block_code'] = abc_list
    asgn_data['avail_code'] = aac_list
    asgn_data['limit_code'] = alc_list
    return asgn_data
}

function dtSAStoJS(dtSAS,dtType='DATE'){
  // accepts SAS unformatted DATE or DATETIME
  // dtType should be used to determine the above
  // -315619200000 is equivalent to +new Date(1960,0,1)
  // 86400000 is equivalent to 24h * 60m * 60s * 1000ms
  if(dtType==='DATE'){
    return new Date(-315619200000 + dtSAS * 86400000);
  } else if (dtType==='DATETIME'){
    return new Date(-315619200000 + dtSAS * 1000);
  } else {
    console.log('Unknown dtType value - ' + dtType);
    return null;
  }
};


function formatSASDate(sasdate) {
    if (sasdate){
        var date = new Date(-315619200000 + sasdate * 86400000)

        var year = date.getFullYear();

        var month = (1 + date.getMonth()).toString();
        month = month.length > 1 ? month : '0' + month;

        var day = date.getDate().toString();
        day = day.length > 1 ? day : '0' + day;

        return year + '/' + month + '/' + day;
    }
    else {
        return ""
    }
}
