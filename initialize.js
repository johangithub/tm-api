const sqlite3 = require('sqlite3').verbose()
var bcrypt = require('bcrypt')
let db  = new sqlite3.Database('./db.db', (err)=> {
    if (err){
        console.error(err.message)
    }
})

var sql = `
CREATE TABLE IF NOT EXISTS user(
email text,
password text,
role text,
hash text,
salt text,
id int
)
`
var users = [
  {
    email: "chan.han.1@us.af.mil",
    password: "password1",
    role: ["admin"],
    id: 999
  },
  {
    email: "caleb.ziegler.1@us.af.mil",
    password: "password2",
    role: ["admin"],
    id: 999
  },
  {
    email: "gregory.anderson.26@us.af.mil",
    password: "password3",
    role: ["admin"],
    id: 999
  },
  {
    email: "dutch.cude@us.af.mil",
    password: "password",
    role: ["assignment_officer"],
    id: 999
  },
]

for (let i=1;i<11;i++){
  users.push({
    email: "commander."+i+"@us.af.mil",
    password: "password",
    role: ["losing_commander", "billet_owner"],
    id: i
  })
  users.push({
    email: "officer."+i+"@us.af.mil",
    password: "password",
    role: ["officer"],
    id: i
  })
  users.push({
    email: "billet.owner."+i+"@us.af.mil",
    password: "password",
    role: ["billet_owner"],
    id: i
  })
}

var sql2 = `
INSERT INTO user(email, password, role, hash, salt, id)
VALUES (?,?,?,?,?,?)
`
db.serialize(()=>{
  db.run('DROP Table IF EXISTS user')
  db.run(sql, [], function(err){
    if (err){
      console.log(err.message)
    }
    console.log(`Table Created`)
  })
  var stmt = db.prepare(sql2)
  for (i = 0;i<users.length;i++){
    var salt = bcrypt.genSaltSync(10)
    var hash = bcrypt.hashSync(users[i].password, salt)
    // var authenticated = bcrypt.compareSync(users[i].password, hash)
    stmt.run(users[i].email,users[i].password, users[i].role.join(','), hash, salt, users[i].id)
  }
  stmt.finalize()
})

db.close()

