import { ApiError } from "../utils/apiError";
import { asyncHandler } from "../utils/asyncHandler";
import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";


export const verifyJWT = asyncHandler(async (req, res, next) => {
    const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "")
    if(!token) {
        throw new ApiError(401, "Unauthorized")
    }
    const decode = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
    
})