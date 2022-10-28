const {StatusCodes} = require('http-status-codes')
const User = require('../model/userModel')
const bcrypt = require('bcryptjs')

const authController = {
    register: async (req,res) =>{
        
        try{
            const { name, email , mobile , password} = req.body

            const encPassword =  await bcrypt.hash(password , 10)

            const newUser = await User.create({
                name,
                email,
                mobile,
                password
            })

            res.status(StatusCodes.OK).json({ msg: "User registered Successfully", data: newUser})
        res.json({ data: { name, email , mobile , password}})
        }catch(err){
            return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({msg: err.message})
        }
    },
    login: async (req,res) =>{
        try{
             res.json({msg: "login"})
        }catch(err){
            return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({msg: err.message})
        }
    },
    logout: async (req,res) =>{
  try{
             res.json({msg: "logout"})
        }catch(err){
            return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({msg: err.message})
        }
    },
    refereshToken: async (req,res) =>{
  try{
             res.json({msg: "refreshToken"})
        }catch(err){
            return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({msg: err.message})
        }
    },
    resetPassword: async (req,res) =>{
  try{
             res.json({msg: "resetPassword"})
        }catch(err){
            return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({msg: err.message})
        }
    },

}
module.exports = authController
