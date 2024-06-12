
const asyncHandler = (requestHandler) => {
    return (req, res, next) => {
        Promise.resolve(requestHandler(req, res, next)).catch((err) => next(err))
    }
}


export { asyncHandler }


//try catch thi
//const asyncHandler = () =>{}
//const ayncHandler =(func)=>()=>{}
//const ayncHandler = (func)=> async ()=>{}

/*
const asyncHandler =(fn)=>async(req,res,next)=>{
    try {
        await fn(req,res,next)
        
    } catch (error) {
        res.status(err.code ||500).json({
            success:false,
            message:error.message
        })
        
    }
}*/