const Router = require('express');
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const {check, validationResult} = require('express-validator');
const config = require('config');
const jwt = require('jsonwebtoken');
const router = new Router();

router.post('/registration',
    [
      check('email', 'Incorrect email').isEmail(),
      check('password', 'Password should be longer than 3 and shorter than 12').isLength({min: 3, max: 12})
    ],
    async (req, res) => {
      try {
        console.log(req);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          return res.status(400).json({message: 'Incorrect request', errors});
        }

        const {email, password} = req.body; // достаем мыло и пароль пользователя из запроса
        const candidate = await User.findOne({email}); // ищем с помощью статического метода есть ли такой пользователь

        if (candidate) { // если он есть, даем знать
          return res.status(400).json({message: `User with email ${email} already exists`});
        }

        const hashPassword = await bcrypt.hash(password, 8); // хэшируем пароль для безопасности
        const user = new User({email, password: hashPassword}); // если новый пользователь, то создаем
        await user.save(); // сохраняем в базе данных
        return res.json({message: 'User has been created!'});

      } catch (e) {
        console.log(e);
        res.send({message: 'Server error!'})
      }
    });

router.post('/login',
    async (req, res) => {
      try {
        const {email, password} = req.body;
        const user = await User.findOne({email});
        if (!user) {
          return res.status(404).json({message: 'User has not been found'});
        }
        const isPassValid = bcrypt.compareSync(password, user.password);
        if (!isPassValid) {
          return res.status(400).json({message: 'Invalid password'});
        }
        const token = jwt.sign({id: user.id}, config.get('secretKey'), {expiresIn: '1h'});

        return res.json({
          token,
          user: {
            id: user.id,
            email: user.email,
            diskSpace: user.diskSpace,
            usedSpace: user.usedSpace
          }
        })
      } catch (e) {
        console.log(e);
        res.send({message: 'Server error!'})
      }
    });

module.exports = router;
