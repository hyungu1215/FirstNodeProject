const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');

const userSchema = mongoose.Schema({
    name : {
        type : String,
        maxlength : 50
    },
    email : {
        type : String,
        trim : true,
        unique : 1
    },
    password : {
        type : String,
        minlength : 5
    },
    lastname : {
        type : String,
        maxlength : 50
    },
    role : {
        type : Number,
        default : 0
    },
    Image : String,
    token : {
        type : String
    },
    tokenExp : {
        type : Number
    }
});

userSchema.pre('save', function (next) {
    var user = this;

    if (user.isModified('password')) {
        // 비밀번호를 암호화 시킨다.
        bcrypt.genSalt(saltRounds, function (err, salt) {
            if (err) {
                return next(err);
            } else {
                bcrypt.hash(user.password, salt, function (err, hash) {
                    if (err) {
                        return next(err);
                    } else {
                        user.password = hash;
                        next();
                    }
                });
            }
        })
    } else {
        next();
    }
})

userSchema.methods.comparePassword = function (plainPassword, cb) {
    // plainPassword : 1213567
    // 암보화된 비밀번호 : $2b$10$TpEusxHZ1eSMDmZb0PL8pubEL9IOR6R9MW579NDHQiFzC68D1a86u
    bcrypt.compare(plainPassword, this.password, function (err, isMatch) {
        console.log("comparing");
        console.log(`hash: ${isMatch}`);
        if (err) {
            return cb(err);
        } else {
            cb(null, isMatch);
        }
        console.log("compared");
    })
}

userSchema.methods.generateToken = function (cb) {
    var user = this;
    console.log('user._id', user._id);

    // jsonwebtoken을 이용해서 token을 생성하기
    var token = jwt.sign(user._id.toHexString(), 'secretToken');
    // user._id + 'secretToken' = token
    // ->
    // 'secretToken' -> user._id

    user.token = token;
    user.save(function (err, user) {
        if (err) {
            return cb(err);
        } else {
            cb(null, user);
        }
    })
}

const User = mongoose.model('User', userSchema)

module.exports = {User}