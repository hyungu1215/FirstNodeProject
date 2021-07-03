const express = require('express');
const app = express();
const port = 5000;

const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');

const {User} = require('./models/User');

// application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({extended : true}));

// application/json
app.use(bodyParser.json());

// application/cookie
app.use(cookieParser());

const mongoose = require('mongoose');
mongoose.connect('mongodb+srv://hgp:phg@19931215@hgp.psnge.mongodb.net/myFirstDatabase?retryWrites=true&w=majority', {
  useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true, useFindAndModify: false
}).then(() => console.log('MongoDB Connected...'))
  .catch(err => console.log(err));

app.get('/', (req, res) => {
  res.send('Hello World! My Name is HG PARK');
})

app.post('/register', (req, res) => {
  // 회원 가입 할 떄 필요한 정보들을 client에서 가져오면
  // 그것들을 데이터 베이스에 넣어준다.

  const user = new User(req.body);

  user.save((err, userInfo) => {
    if (err) {
      return res.json({ sucess : false, err });
    } else {
      return res.status(200).json({
        sucess : true
      });
    }
  });
});

app.post('/login', (req, res) => {
  // 요청된 이메일을 데이타 베이스에서 찾는다.
  User.findOne({ email : req.body.email }, (err, user) => {
    console.log(user);
    if (!user) {
      return res.json({
        loginSuccess: false,
        message: "제공된 이메일에 해당하는 유저가 없습니다."
      });
    } else {
      // 요청된 이메일이 데이터 베이스에 있다면 비밀번호가 맞는 비밀번호 인지 확인.
      user.comparePassword(req.body.password, (err, isMatch) => {
        console.log(`err: ${err}`);
        console.log(`isMatch: ${isMatch}`);

        if (!isMatch) {
          return res.json({
            loginSuccess : false,
            message : "비밀번호가 들렸습니다."
          });
        }

        // 비밀번호까지 맞다면 토큰을 생성하기.
        user.generateToken((err, user) => {
          if (err) {
            return res.status(400).send(err);
          } else {
            // 토큰을 저장한다. 어디에? 오컬스토리지, 세션, 쿠키
            res.cookie('x_auth', user.token)
            .status(200)
            .json({
              loginSuccess : true,
              userId : user._id
            });
          }
        });
      });
    }
  });
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});