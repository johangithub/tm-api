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

app.get('/', (req, res)=> {
    res.send('Hello! The API is at http://localhost:' + port + '/api')
})

// API ROUTES -------------------
var apiRoutes = express.Router()

//The middleware is not applied here, because we cannot apply token-requiring
//middleware when they first login and authenticate
apiRoutes.post('/authenticate', (req, res)=>{
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

apiRoutes.get('/officers', (req, res)=>{
    var rowid = Math.floor(Math.random() * 1000) + 1  
    var sqlget = `SELECT * from officers where rowid = ?`
    db.get(sqlget, rowid, (err, row)=>{
        if (err){
            throw err
        }
        else {
            var data = {}
            for (d in row){
                if(row[d] != null && typeof(row[d]) == 'object'){
                    data[d] = new Buffer(row[d], 'binary').toString('utf-8')
                } else if (row[d] != null){
                    data[d] = row[d]
                }
            }
            data['language'] = language_data_parse(data)
            data['general'] = general_data_parse(data)
            data['projected'] = projection_data_parse(data)
            data['duty'] = duty_data_parse(data)
            data['asgn_code'] = asgn_code_parse(data)
            data['service_dates'] = service_dates_parse(data)
            data['rated'] = rated_data_parse(data)
            data['courses'] = course_data_parse(data)
            data['adsc'] = adsc_data_parse(data)
            data['degree'] = degree_data_parse(data)
            data['pme'] = pme_data_parse(data)
            data['joint'] = joint_data_parse(data)
            data['special_experience'] = special_experience_parse(data)
            data.rowid = rowid

            res.json({
                success: true,
                data: data
            })
        }
    })
})
apiRoutes.get('/officers/:officerId', (req, res)=>{
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
app.listen(port, '0.0.0.0')
console.log('Magic happens at http://localhost:' + port)


function general_data_parse(data){
    general_data = {}
    general_data['proj_grade'] = data['_grade_proj']
    general_data['grade'] = data['_grade']
    general_data['component'] = data['_component_t']
    general_data['func_cat'] = data['_func_cat']
    general_data['comp_cat'] = data['_comp_cat']
    general_data['record_status'] = data['_record_status']
    general_data['accounting_status'] = data['_accounting_status']
    general_data['posn'] = data['_position_number']
    general_data['aef'] = data['_aef']
    general_data['aef_start_date'] = formatSASDate(data['_aef_start_Date'])
    general_data['aef_stop_date'] = formatSASDate(data['_aef_stop_Date'])
    general_data['short_tour_num'] = data['_short_tour_nbr'] ? data['_short_tour_nbr'].trim() : 0 
    delete data['_grade_proj']
    delete data['_grade']
    delete data['_component_t']
    delete data['_func_cat']
    delete data['_comp_cat']
    delete data['_record_status']
    delete data['_accounting_status']
    delete data['_position_number']
    delete data['_aef']
    delete data['_aef_start_date']
    delete data['_aef_stop_date']
    delete data['_short_tour_nbr']
    
    return general_data
}

function projection_data_parse(data){
    proj_data = {}
    proj_asgn = {}
    proj_asgn['pas'] = data['_pas_proj']
    proj_asgn['afsc'] = data['_afsc_selected']
    proj_asgn['asd'] = formatSASDate(data['_asd'])
    proj_asgn['pdd'] = formatSASDate(data['_pdd'])
    proj_asgn['rnltd'] = formatSASDate(data['_rnltd'])

    delete data['_pas_proj']
    delete data['_afsc_selected']
    delete data['_asd']
    delete data['_pdd']
    delete data['_rnltd']

    proj_duty = {}
    proj_duty['eff_date'] = formatSASDate(data['_duty_status_proj_eff_date'])
    proj_duty['exp_date'] = formatSASDate(data['_duty_status_proj_exp_date'])
    proj_duty['status'] = data['_duty_status_proj']
    proj_duty['title_pending'] = data['_duty_title_pending']
    proj_duty['cmd_lvl_pending'] = data['_cmd_lvl_pending']
    proj_duty['afsc_pending'] = data['_dafsc_pending']
    proj_duty['eff_date_pending'] = formatSASDate(data['_duty_eff_date_pending'])
    delete data['_duty_status_proj_eff_date']
    delete data['_duty_status_proj_exp_date']
    delete data['_duty_status_proj']
    delete data['_duty_title_pending']
    delete data['_cmd_lvl_pending']
    delete data['_dafsc_pending']
    delete data['_duty_eff_date_pending']

    proj_course = []
    var i = 1
    while (data['_projected_training_'+i]){
        course_temp = {}
        course_temp['course'] = data['_projected_training_'+i]
        course_temp['course_ct'] = data['_projected_training_ct_'+i]
        course_temp['start_date'] = formatSASDate(data['_projected_training_start_date_'+i])
        course_temp['grad_date'] = formatSASDate(data['_projected_training_grad_date_'+i])
        delete data['_projected_training_'+i]
        delete data['_projected_training_ct_'+i]
        delete data['_projected_training_start_date_'+i]
        delete data['_projected_training_grad_date_'+i]
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
        if (data['hist_unit_'+i] || data['_duty_hist_loc_'+i]){
        // If orgnum exists, trim
        data['hist_org_num_'+i] ? temp['org_num'] = data['hist_org_num_'+i].trim() : null
        temp['org_type'] = data['hist_org_type_'+i]
        temp['org_level'] = data['hist_org_level_'+i]
        temp['org_det'] = data['hist_org_det_'+i]
        temp['org_majcom'] = data['hist_majcom_'+i]
        temp['unit'] = data['hist_unit_'+i]
        temp['duty_title'] = data['_duty_hist_title_'+i]
        temp['dafsc'] = data['_duty_hist_dafsc_'+i]
        temp['location'] = data['_duty_hist_loc_'+i]
        temp['country_state'] = data['_duty_hist_cntryst_'+i]
        temp['command_level'] = data['_duty_hist_cmd_lvl_'+i]
        temp['eff_date'] = formatSASDate(data['_duty_hist_eff_date_'+i])
        duty_history.push(temp)
        delete data['hist_org_num_'+i] 
        delete data['hist_org_type_'+i] 
        delete data['hist_org_level_'+i] 
        delete data['hist_org_det_'+i] 
        delete data['hist_majcom_'+i] 
        delete data['hist_unit_'+i] 
        delete data['_duty_hist_eff_date_'+i]
        delete data['_duty_hist_title_'+i]
        delete data['_duty_hist_dafsc_'+i]
        delete data['_duty_hist_org_num_'+i]
        delete data['_duty_hist_org_suffix_'+i]
        delete data['_duty_hist_org_type_'+i]
        delete data['_duty_hist_org_level_'+i]
        delete data['_duty_hist_majcom_'+i]
        delete data['_duty_hist_cmd_lvl_'+i]
        delete data['_duty_hist_cntryst_'+i]
        delete data['_duty_hist_loc_'+i]
        }
    }

    var duty_exp = []
    var i = 1
    for (let i =1; i<=15;i++){
        exp_temp = {}
        exp_temp['duty_title'] = data['_exp_duty_afs_title_'+i]
        exp_temp['duty_years'] = Math.round(data['_exp_duty_calc_yrs_in_afs_'+i] * 10 ) / 10
        //delete data['_exp_duty_afs_title_'+i]
        //delete data['_exp_duty_calc_yrs_in_afs_'+i]
        if (exp_temp['duty_title']){
            duty_exp.push(exp_temp)
        }
        delete data['_exp_duty_afs_title_'+i]
        delete data['_exp_duty_calc_yrs_in_afs_'+i]
    }


    duty_data['status'] = data['_duty_status']
    duty_data['status_ct'] = data['_duty_status_ct']
    duty_data['title'] = data['_duty_title']
    duty_data['dafsc'] = data['_afsc_duty']
    duty_data['afsc_1'] = data['_afsc_1']
    duty_data['afsc_2'] = data['_afsc_2']
    duty_data['afsc_3'] = data['_afsc_3']
    duty_data['unit'] = data['org_unit']
    duty_data['org_num'] = data['org_num']
    duty_data['org_type'] = data['org_type']    
    duty_data['org_level'] = data['org_level']
    duty_data['org_det'] = data['org_det']
    duty_data['pas'] = data['_pas']
    duty_data['core_group'] = data['_core_derived_group']
    duty_data['status_expire_date'] = formatSASDate(data['_duty_status_exp_date'])
    delete data['_duty_status']
    delete data['_duty_status_ct']
    delete data['_duty_title']
    delete data['_afsc_duty']
    delete data['_afsc_1']
    delete data['_afsc_2']
    delete data['_afsc_3']
    delete data['org_unit']
    delete data['org_num']
    delete data['org_type']    
    delete data['org_level']
    delete data['org_det']
    delete data['_pas']
    delete data['_core_derived_group']
    delete data['_duty_status_exp_date']

    duty_data['history'] = duty_history
    duty_data['experience'] = duty_exp
    return duty_data
}

function service_dates_parse(data){
    var service_dates = {}
    service_dates_column = ['_das', '_ddlds', '_duty_status_eff_date', '_odsd', '_strd', '_dos', '_ead', '_pay_date', '_tafcsd',
    '_tfcsd', '_grade_eff_date', '_dor', '_tafmsd', '_deros', '_cc_date', '_retsep_eff_date_proj']
    for (let i=0;i<service_dates_column.length;i++){
        service_dates[service_dates_column[i]] = formatSASDate(data[service_dates_column[i]])
        delete data[service_dates_column[i]]
    }
    return service_dates
}

function rated_data_parse(data){
    var rated_data = {}
    rated_data['aero_rating'] = data['_aero_rating']
    rated_data['aero_rating_ct'] = data['_aero_rating_ct']
    rated_data['flt_activity_code'] = data['_flt_activity_code']
    rated_data['gates_curr'] = data['_gates_curr']
    rated_data['flt_hrs_combat'] = data['_flt_hrs_combat']
    rated_data['flt_hrs_instr'] = data['_flt_hrs_instr']
    rated_data['flt_hrs_total'] = data['_flt_hrs_total']
    rated_data['avn_service_code'] = data['_avn_service_code']
    rated_data['avn_service_code_ct'] = data['_avn_service_code_ct']
    rated_data['rdtm'] = data['_rdtm']
    rated_data['aircrew_position_id'] = data['_aircrew_position_id']
    rated_data['acp_status'] = data['_acp_status']
    rated_data['acp_status_ct'] = data['_acp_status_ct']
    rated_data['avn_service_date'] = formatSASDate(data['_avn_service_date'])
    rated_data['acp_elig_date'] = formatSASDate(data['_acp_elig_date'])
    rated_data['acp_effective_date'] = formatSASDate(data['_acp_effective_date'])
    rated_data['acp_stop_date'] = formatSASDate(data['_acp_stop_date'])
    rated_data['aero_rating_date'] = formatSASDate(data['_aero_rating_date'])
    rated_data['return_to_fly_date'] = formatSASDate(data['_return_to_fly_date'])

    delete data['_aero_rating']
    delete data['_aero_rating_ct']
    delete data['_flt_activity_code']
    delete data['_gates_curr']
    delete data['_flt_hrs_combat']
    delete data['_flt_hrs_instr']
    delete data['_flt_hrs_total']
    delete data['_avn_service_code']
    delete data['_avn_service_code_ct']
    delete data['_rdtm']
    delete data['_aircrew_position_id']
    delete data['_acp_status']
    delete data['_acp_status_ct']
    delete data['_avn_service_date']
    delete data['_acp_elig_date']
    delete data['_acp_effective_date']
    delete data['_acp_stop_date']
    delete data['_aero_rating_date']
    delete data['_return_to_fly_date']

    aircraft_history = []
    var i = 1
    while (data['_acft_hist_'+i]){
        acft_temp = {}
        acft_temp['aircraft'] = data['_acft_hist_'+i]
        acft_temp['aircraft_date_flown'] = formatSASDate(data['_acft_hist_date_flown_'+i])
        acft_temp['hours'] = Math.round(data['_acft_hist_hrs_'+i] * 10 ) / 10
        aircraft_history.push(acft_temp)
        delete data['_acft_hist_'+i]
        delete data['_acft_hist_date_flown_'+i]
        delete data['_acft_hist_hrs_'+i]
        i += 1
    }
    rated_data['aircraft_history'] = aircraft_history
    return rated_data
}

function degree_data_parse(data){
    var degree_data = {}
    var i = 1
    var degree_hist = []
    while (data['_acad_spec_'+i]){
        var degree_temp = {}
        degree_temp['degree'] = data['_acad_spec_'+i]
        degree_temp['degree_ct'] = data['_acad_spec_ct_'+i]
        degree_temp['level'] = data['_acad_educ_level_'+i]
        degree_temp['method'] = data['_acad_educ_meth_'+i]
        degree_temp['school'] = data['_acad_educ_inst_'+i]
        degree_temp['date'] = formatSASDate(data['_acad_educ_date_'+i])
        degree_hist.push(degree_temp)
        delete data['_acad_spec_'+i]
        delete data['_acad_spec_ct_'+i]
        delete data['_acad_educ_level_'+i]
        delete data['_acad_educ_meth_'+i]
        delete data['_acad_educ_inst_'+i]
        delete data['_acad_educ_date_'+i]
        i += 1
    }
    degree_data['history'] = degree_hist
    degree_data['highest'] = data['_acad_edu_level_high']
    delete data['_acad_edu_level_high']
    return degree_data
}

function course_data_parse(data){
    var course_data = []
    var i = 1
    while (data['_prof_spec_crse_'+i]){
        course_temp = {}
        course_temp['course'] = data['_prof_spec_crse_'+i]
        course_temp['date'] = formatSASDate(data['_prof_spec_crse_date_'+i])
        delete data['_prof_spec_crse_'+i]
        delete data['_prof_spec_crse_date_'+i]
        course_data.push(course_temp)
        i+=1
    }
    return course_data
}

function pme_data_parse(data){
    var pme_data = {}
    var i = 1
    var pme_hist = []
    while (data['_pme_'+i]){
        var pme_temp = {}
        pme_temp['course'] = data['_pme_'+i]
        pme_temp['date'] = formatSASDate(data['_pme_date_'+i])
        pme_temp['method'] = data['_pme_method_'+i]
        pme_temp['level'] = data['_pme_level_'+i]
        delete data['_pme_'+i]
        delete data['_pme_date_'+i]
        delete data['_pme_method_'+i]
        delete data['_pme_level_'+i] 
        pme_hist.push(pme_temp)
        i+=1
    }
    pme_data['history'] = pme_hist
    pme_data['pme_highest'] = data['_pme_highest']
    delete data['_pme_highest']
    return pme_data
}

function joint_data_parse(data){
    var joint_data = {}
    var joint_hist = []
    var i = 1
    while (data['_jda_start_date_'+i]){
        joint_temp = {}
        joint_temp['start_date'] = formatSASDate(data['_jda_start_date_'+i])
        joint_temp['stop_date'] = formatSASDate(data['_jda_stop_date_'+i])
        joint_temp['type'] = data['_jda_tour_type_'+i]
        joint_temp['credit'] = data['_jda_tour_credit_'+i]
        joint_temp['reason'] = data['_jda_completion_rsn_'+i]
        joint_temp['posn'] = data['_jdamis_posn_number_'+i]
        joint_hist.push(joint_temp)
        delete data['_jda_start_date_'+i]
        delete data['_jda_stop_date_'+i]
        delete data['_jda_tour_type_'+i]
        delete data['_jda_tour_credit_'+i]
        delete data['_jda_completion_rsn_'+i]
        delete data['_jdamis_posn_number_'+i]
        i += 1
    }
    joint_data['history'] = joint_hist
    joint_data['jso_code'] = data['_jso_spec_code']
    joint_data['jda_flag'] = data['_jda_flag']
    joint_data['jso_jsonum_status'] = data['_jso_jsonum_status']
    delete data['_jso_spec_code']
    delete data['_jda_flag']
    delete data['_jso_jsonum_status']

    return joint_data

}

function adsc_data_parse(data){
    var adsc_data = []
    var i = 1
    while (data['_adsc_'+i]){
        var adsc_temp = {}
        adsc_temp['adsc'] = data['_adsc_'+i]
        adsc_temp['date'] = formatSASDate(data['_adsc_date_'+i])
        adsc_data.push(adsc_temp)
        delete data['_adsc_'+i]
        delete data['_adsc_date_'+i]
        i += 1
    }
    return adsc_data
}

function special_experience_parse(data){
    var spec_exp = {}
    var nei_list = []
    var i = 1
    while (data['_nei_'+i]){
        nei_temp = {}
        nei_temp['nei'] = data['_nei_'+i]
        nei_temp['start_date'] = formatSASDate(data['_nei_start_date_'+i])
        nei_temp['stop_date'] = formatSASDate(data['_nei_stop_date_'+i])
        nei_list.push(nei_temp)
        delete data['_nei_'+i]
        delete data['_nei_start_date_'+i]
        delete data['_nei_stop_date_'+i]
        i += 1
    }

    var i = 1
    var sei_list = []
    while (data['_sei_gen_'+i]){
        sei_temp = {}
        sei_temp['sei'] = data['_sei_gen_'+i]
        sei_list.push(sei_temp)
        delete data['_sei_gen_'+i]
        i += 1
    }

    spec_exp['sei_duty'] = data['_sei_duty']
    spec_exp['nuclear'] = nei_list
    spec_exp['sei'] = sei_list
    delete data['_sei_duty']

    var acq_data = {}
    acq_data['career_level'] = data['_auth_acq_career_lvl']
    acq_data['posn_cat'] = data['_auth_acq_posn_cat']
    acq_data['posn_type'] = data['_auth_acq_posn_type']
    spec_exp['acquisitions'] = acq_data
    delete data['_auth_acq_career_lvl']
    delete data['_auth_acq_posn_cat']
    delete data['_auth_acq_posn_type']

    return spec_exp
}

function language_data_parse(data){
    var lang_data = {}
    var lang_list = []
    for (let i=1;i<=5;i++){
        var lang_temp = {}
        lang_temp['id'] = data['_lang_id_'+i]
        lang_temp['listen'] = data['_lang_listen_comp_'+i]
        lang_temp['read'] = data['_lang_read_comp_'+i]
        lang_temp['date'] = formatSASDate(data['_lang_test_date_'+i])
        delete data['_lang_id_'+i]
        delete data['_lang_listen_comp_'+i]
        delete data['_lang_read_comp_'+i]
        delete data['_lang_speak_comp_'+i]
        delete data['_lang_test_date_'+i]
        if (lang_temp['id']){
            lang_list.push(lang_temp)
        }
    }
    lang_data['list'] = lang_list 
    lang_data['dlab_score'] = Number(data['_lang_dlab_score'])
    lang_data['dlab_date'] = formatSASDate(data['_lang_dlab_date'])
    delete data['_lang_dlab_score']
    delete data['_lang_dlab_date']
    return lang_data
}
function asgn_code_parse(data){
    var asgn_data = {}
    var i = 1
    var abc_list = []
    while (data['_abc_date_'+i]){
        var abc_temp={}
        abc_temp['date'] = formatSASDate(data['_abc_date_'+i])
        abc_temp['code'] = data['_abc_'+i]
        abc_list.push(abc_temp)
        delete data['_abc_date_'+i]
        delete data['_abc_'+i]
        i+=1
    }

    // Somehow empty assignment block code is being brought in
    while (i<=10){
        delete data['_abc_'+i]
        i+=1
    }

    var i = 1
    var aac_list = []
    while (data['_aac_date_'+i]){
        var aac_temp={}
        aac_temp['date'] = formatSASDate(data['_aac_date_'+i])
        aac_temp['code'] = data['_aac_'+i]
        aac_list.push(aac_temp)
        delete data['_aac_date_'+i]
        delete data['_aac_'+i]
        i+=1
    }

    var i = 1
    var alc_list = []
    while (data['_alc_date_'+i]){
        var alc_temp={}
        alc_temp['date'] = formatSASDate(data['_alc_date_'+i])
        alc_temp['code'] = data['_alc_'+i]
        alc_list.push(alc_temp)
        delete data['_alc_date_'+i]
        delete data['_alc_'+i]
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