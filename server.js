require('dotenv').config()
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const assert = require('assert')
const fileUpload = require('express-fileupload');
const {StatusCodes} = require('http-status-codes')
const  connectDB = require('./db/index')


//port
const PORT = process.env.PORT

//ref
const app = express()

//body parser

app.use(express.urlencoded({extended: true})) // when we not get data this only problem
app.use(express.json())

//middleware

app.use(cors())
app.use(cookieParser(process.env.TOKEN_SECRET)) // add token only for signed cookies

app.use(
    fileUpload({
        useTempFiles: true
    })
)

//route modules

const authRoute = require('./route/authRoute');
const userRoute = require('./route/userRoute');


//primary route

app.use('/api/v1/auth', authRoute)
app.use('/api/v1/user', userRoute)


const start = async () => {
    try {
        await connectDB()
        app.listen(PORT , ()=>{
            console.log(`server is listining @ http://localhost:${PORT}`)
        })

    }catch(err) {
        return res.status(StatusCodes.INTERNAL_SERVAL_ERROR).json({msg: err.message})
        
    }

}
start();



