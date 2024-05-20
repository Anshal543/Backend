import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/apiError.js';
import { User } from '../models/user.model.js';


const registerUser = asyncHandler(async (req, res, next) => {
    // get user detail from frontend
    // validation of user detail - not empty
    // check if user already exists : email, username
    // check for images, check for avatar
    // upload them to cloudinary
    // create user object, create entry in db
    // remove password and refresh token field from response
    // check for user creation, return response

    const { username, email, fullName, password } = req.body;
    console.log("email", email);

    if ([username, email, fullName, password].some(field => field?.trim() === "")) {
        throw new ApiError(400, "All fields are required");
    }

    const existedUser = User.findOne({
        $or: [{ email }, { username }]
    })


});

export { registerUser };