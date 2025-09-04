import jwt from "jsonwebtoken";
import { asyncHandler } from "../utils/async-handler.js";
import { ApiResponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-error.js";
import { User } from "../models/user.model.js";
import { emailVerificationMailgenContent, sendEmail } from "../utils/mail.js";

const generateAccessAndRefreshToken = async (userId) => {
  try {
    const user = await User.findById(userId);
    const AccessToken = user.generateAccessToken();
    const RefreshToken = user.generateRefreshToken();
    user.refreshToken = RefreshToken;

    await user.save({ validateBeforeSave: false });
    return { AccessToken, RefreshToken };
  } catch (error) {
    throw new ApiError(500, "Something went wrong", [error.message]);
  }
};
const registerUser = asyncHandler(async (req, res) => {
  const { email, username, password, role } = req.body;

  //   checking if the user is already exist
  const existingUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existingUser) {
    throw new ApiError(400, "User with email or username already exists");
  }

  const user = await User.create({
    email,
    password,
    username,
    isEmailVerified: false,
  });

  const { unhashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();
  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  await sendEmail({
    email: user?.email,
    subject: "Email Verification",
    mailgenContent: emailVerificationMailgenContent(
      user?.username,
      `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unhashedToken}`,
    ),
  });

  const createdUser = await User.findById(user._id).select(
    "-password -emailVerificationToken -emailVerificationExpiry -refreshToken",
  );

  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registering user ");
  }

  const { AccessToken, RefreshToken } = await generateAccessAndRefreshToken(
    createdUser._id,
  );

  return res
    .status(201)
    .json(
      new ApiResponse(
        201,
        { user: createdUser, AccessToken },
        "User registered successfully and verification email has been sent to your email",
      ),
    );
});

const login = asyncHandler(async (req, res) => {
  const { email, password, username } = req.body;
  if (!email && !username) {
    throw new ApiError(400, "Email or username are required");
  }
  if (!password) {
    throw new ApiError(400, "Password is required");
  }
  const user = await User.findOne({ email });
  if (!user) {
    throw new ApiError(404, "User not found");
  }
  const isPasswordCorrect = await user.isPasswordCorrect(password);
  if (!isPasswordCorrect) {
    throw new ApiError(401, "Invalid password");
  }

  const { AccessToken, RefreshToken } = await generateAccessAndRefreshToken(
    user._id,
  );
  const loggedInUser = await User.findById(user._id).select(
    "-password -emailVerificationToken -emailVerificationExpiry -refreshToken",
  );
  if (!loggedInUser) {
    throw new ApiError(500, "Something went wrong while logging in user");
  }
  const options = {
    httpOnly: true,
    secure: true,
  };
  return res
    .status(200)
    .cookie("accessToken", AccessToken, options)
    .cookie("refreshToken", RefreshToken, options)
    .json(
      new ApiResponse(
        200,
        { user: loggedInUser },
        "User logged in successfully",
      ),
    );
});
export { registerUser, login };
