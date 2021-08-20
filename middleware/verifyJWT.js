const jwt = require('jsonwebtoken')

//token verifying middleware

module.exports = function(req,res,next){
    const token = req.cookies.token;
    if(token){
        jwt.verify(token,process.env.SECRET_KEY,(err,decodedToken)=>{
            if(err){
                res.redirect('/login')
            }else{
                next()
            }
        })
    }else{
        res.redirect('/login')
    }
}