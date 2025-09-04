import { Router } from "express";
import { registerUser, login } from "../controllers/auth.controller.js";
import {
  userRegisterValidator,
  userLoginValidator,
} from "../validators/index.js";
import { validate } from "../middlewares/validator.middleware.js";

const router = Router();

router.route("/register").post(userRegisterValidator(), validate, registerUser);
router.route("/login").post(userLoginValidator(), validate, login);
export default router;
