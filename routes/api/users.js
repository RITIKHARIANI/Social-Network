const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');

const User = require('../../models/User');
//require('express-validator/check') is deprecated

// @route  POST api/users
// @desc   Register user
// @access Public
router.post(
  '/',
  [
    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check(
      'password',
      'Please enter a password with 6 or more characters'
    ).isLength({ min: 6 }),
  ],
  async (req, res) => {
    //used express.json({extended: false to make it access req.body})
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() }); //bad request
    }

    const { name, email, password } = req.body;

    try {
      let user = await User.findOne({ email });

      //see if user exists
      if (user) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'User already exists' }] });
      }
      // get users gravatar
      const avatar = gravatar.url(email, {
        //normalize(
        s: '200', //size
        r: 'pg', //rating of pic by censor board
        d: 'mm', //default
      });
      //{ forceHttps: true }
      //);
      user = new User({
        name,
        email,
        avatar,
        password,
      });

      //Encrypt password
      const salt = await bcrypt.genSalt(10); //random data to hash the password

      user.password = await bcrypt.hash(password, salt); //hashing the password

      await user.save();

      //Return jsonwebtoken (to login the user as soon as he registers)
      const payload = {
        user: {
          id: user.id,
        },
      };

      jwt.sign(
        payload,
        config.get('jwtSecret'),
        { expiresIn: '5 days' },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (err) {
      console.log(err.message);
      res.status(500).send('Server error');
    }
  }
);

module.exports = router;
