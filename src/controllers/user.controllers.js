const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sendEmail = require('../utils/sendEmail');
const EmailCode = require('../models/EmailCode');

const getAll = catchError(async(req, res) => {
    const user = req.User;
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async(req, res) => {
    const {firstName, lastName, email, password, country, image, frontBaseUrl} = req.body;
    const encrytedPassword= await bcrypt.hash(password,10);
    const result = await User.create({
        firstName,
        lastName,
        email,
        password : encrytedPassword,
        country,
        image

    });   
    const code = require('crypto').randomBytes(32).toString("hex");
    const link = `${frontBaseUrl}/auth/verify_email/${code}`
    
    await  EmailCode.create({
        code,
        userId: result.id
    });

    await sendEmail({
        to: email,
        subject: "verificate email for user app",
        html: `
        <h1>Hola ${firstName}${lastName}/h1>
        <p>ñldsjDSJFLDSÑJFDÑSKÑDLCKXZLÑCKLZXÑMKLÑ</p> 
        <a href="${link}">${link}</a>
        `
    })
    return res.status(201).json(result);
});


const getOne = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if(!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    await User.destroy({ where: {id} });
    return res.sendStatus(204);
});

const update = catchError(async(req, res) => {
    const { id } = req.params;
    const {firstName, lastName} = req.body;
    const result = await User.update(
        {firstName, lastName},
       
        { where: {id}, returning: true }
    );
    if(result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});
const login = catchError(async(req, res) => {
    const {email, password, isVerified } = req.body;
    const user = await User.findOne ({where: {email}})
    if(!user) return res.status(401).json({ message: "Email invalido"})
    const isValid = await bcrypt.compare(password, user.password);
    if(!isValid) return res.status(401).json({ message: "contraseña invalida"})
    if(!user.isVerified) return res.status(401).json({ message: "Usuario no verificado"})
    const token = jwt.sign(
    {user},
    process.env.TOKEN_SECRET,
    {expiresIn: "1d"}

    )
    return res.json({user, token})
});

const getLoggedUser = catchError(async(req, res) =>{
    const user = req.user;
    return res.json(user)
});
const verifyEmail = catchError(async(req, res) =>{
    const {code} = req.params;
    const emailCode = await EmailCode.findOne({where: {code}});
    if(!emailCode) return res.status(401).json({message: "Invalid code"});
    const user = await User.update(
        {isVerified: true},
        {where:{id: emailCode.userId}, returning:true}
    );
    await emailCode.destroy();
    return res.json(user);

});


User.prototype.toJSON = function () {
    const values = Object.assign({}, this.get());
    delete values.password;
    return values;
}

module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    login,
    verifyEmail,
    getLoggedUser
}