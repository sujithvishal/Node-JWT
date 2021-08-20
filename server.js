const dotenv = require('dotenv');
dotenv.config()
const express = require('express');
const app = express();
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cookieParser =require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const User = require('./model/userModel')
const verifyJWT = require('./middleware/verifyJWT')

//Database connection
mongoose.connect(process.env.DATABASE_URL,{useNewUrlParser: true, useUnifiedTopology: true })
.then(result => app.listen(process.env.PORT||3000))
.catch(err => console.log(err))

//Middlewares
app.use(cookieParser())
app.use(bodyParser.urlencoded({extended:false}))
app.set('view engine','ejs');

//Create JWT Token
const createToken = (_id)=>{
    return jwt.sign({_id},process.env.SECRET_KEY)
}

const getUser = (req,res,next)=>{
    const token = req.cookies.token;
    if(token){
        jwt.verify(token,process.env.SECRET_KEY,async(err,decodedToken)=>{
            if(err){
                res.locals.user = null;
                res.render('login')
            }else{
                res.locals.user = await User.findById(decodedToken._id)
                next();
            }
        })
    }else{
        next()
    }
}
//Middleware
app.use('*',getUser);

//GET Routes
app.get('/register',(req,res)=>{
    res.render('register')
})
app.get('/login',(req,res)=>{
    res.render('login')
})
app.get('/',verifyJWT,(req,res)=>{
    res.render('index',{user:res.locals.user})
})
app.get('/logout',(req,res)=>{
    // res.cookie('token','',{maxAge:1})
    res.clearCookie('token');
    res.redirect('/login')
})


//POST Routes
app.post('/login',async(req,res)=>{
    const user = await User.findOne({email:req.body.email})
    if(user){
        const result = bcrypt.compareSync(req.body.password,user.password)
        if(result){
            try{
                const token = createToken(user._id)
                res.cookie('token',token);
                res.redirect('/')
            }catch(err){
                res.status(400).json(err)
            }
        }else{
            res.status(400).json({error:'password incorrect'})
        }
    }else{
        res.redirect('/register')
    }
})

app.post('/register',async(req,res)=>{
    const hashedPassword  = await bcrypt.hash( req.body.password,10)  
    const user = new User({
        email:req.body.email,
        password:hashedPassword
    })
    user.save((err,user)=>{
        if(err)console.log(err)
        else{
            try{
                const token = createToken(user._id);
                res.cookie('token',token);
                res.redirect('/')
            }catch(err){
                res.status(400).json(err)
            }
        }
    })
})