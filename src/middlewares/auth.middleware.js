import { User } from "../models/user.model.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import jwt from "jsonwebtoken";
export const verifyJWT = asyncHandler(async (req, res, next) => {
  const token =
    req.cookies?.accessToken ||
    req.headers("Authorization")?.replace("Bearer ", "");
  if (!token) {
    throw new ApiError((401, "Unauthorized Request"));
  }
  try {
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const user = await User.findById(decodedToken.id).select(
      "-password -refreshToken -emailVerificationToken -emailVerificationExpiry -forgotPasswordToken -forgotPasswordExpiry",
    );
    if (!user) {
      throw new ApiError(401, "Unauthorized Request");
    }
    req.user = user;
    next();
  } catch (error) {
    throw new ApiError(401, "Unauthorized Request");
  }
});
