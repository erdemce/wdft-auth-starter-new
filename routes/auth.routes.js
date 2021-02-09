const router = require("express").Router();
const bcrypt = require('bcryptjs');
const UserModel = require('../models/User.model')

/* GET signin page */
router.get("/signin", (req, res, next) => {
    res.render('auth/signin.hbs')
});

/* GET signup page */
router.get("/signup", (req, res, next) => {
  res.render('auth/signup.hbs')
});

// Handle POST requests to /signup
router.post("/signup", (req, res, next) => {
     const {name, email, password} = req.body
     //validate first

     if(!name.length||!email.length||!password.length){
         res.render("auth/signup",{msg:"Please enter all fields"})
        return;
     }

     let re = /\S+@\S+\.\S+/;
      if(!re.test(email)){
        res.render("auth/signup",{msg:"Email not in valid format"})
        return;
      };

        // at least one number, one lowercase and one uppercase letter
        // at least eight characters

      let isPas =/(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}/;
      if(!isPas.test(password)){
        res.render("auth/signup",{msg:"pass not in valid format"})
        return;
      };

        let salt = bcrypt.genSaltSync(10);
        let hash = bcrypt.hashSync(password, salt);
        UserModel.create({name, email, password: hash})
           .then(() => {
               res.redirect('/')
           })
           .catch((err) => {
               next(err)
           })
});

// Handle POST requests to /signin
router.post("/signin", (req, res, next) => {
    const { email, password} = req.body

    UserModel.findOne({email:email})
    .then((result)=>{
        //if user exists
        if(result){
            bcrypt.compare(password, result.password)
            .then((isMatching)=>{
                if(isMatching){
                    req.session.loggedInUser = result
        
                    res.redirect("/profile")
                }else{
                    res.render("auth/signin.hbs",{msg:"Passwords dont match"})
                }
            })
        }
        else{
            res.render("auth/signin.hbs",{msg:"Email does not exists"})
        }
    })
    .catch((err)=>{
        next(err)
    })
});


const checkLoggedInUser=(req,res,next)=>{
    if(req.session.loggedInUser){
        next()
    }
    else{
        res.redirect("/signin")
    }
}

router.get("/profile",checkLoggedInUser,(req,res)=>{
    let email = req.session.loggedInUser.email
    res.render("profile.hbs",{email})
})

router.get("/logout", (req,res,next)=>{
    req.session.destroy();
    res.redirect("/");
})

module.exports = router;

// And finally don't forget to link this router in your middleware at the bottom of app.js where the other routes are defined