const Router = require('express');
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const {check, validationResult} = require('express-validator');
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

        const hashPassword = await bcrypt.hash(password, 15); // хэшируем пароль для безопасности
        const user = new User({email, password: hashPassword}); // если новый пользователь, то создаем
        await user.save(); // сохраняем в базе данных
        return res.json({message: 'User has been created!'});

      } catch (e) {
        console.log(e);
        res.send({message: 'Server error!'})
      }
    });

module.exports = router;
