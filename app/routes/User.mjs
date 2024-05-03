import express from "express";

const userRouter = express.Router();

userRouter.get('/',function (req, res, next) {
    res.send('Hello my friend');
});

export default userRouter;