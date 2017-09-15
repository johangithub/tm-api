var speakeasy = require('speakeasy');
module.exports ={
  generateSecret: ()=>{
    var secret = speakeasy.generateSecret({length: 20});
    return secret
  },
  generateToken: ()=>{
    var token = speakeasy.totp({
      secret: secret.base32,
      encoding: 'base32',
      algorithm: 'sha256',
      name: 'JoeHan.com'
    });
    console.log(token);
  },
  verifyToken: (base32secret, userToken)=>{
    speakeasy.totp.verifyDelta( {
      secret: base32secret,
      encoding: 'base32',
      token: userToken,
      window: 2
    })
  }
}

