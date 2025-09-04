import Mailgen from "mailgen";
import nodemailer from "nodemailer";

const sendEmail = async (options) => {
  const mailGenerator = new Mailgen({
    theme: "default",
    product: {
      name: "Task Manager",
      link: "https://taskmanagelink.com",
    },
  });

  const emailTextual = mailGenerator.generatePlaintext(options.mailgenContent);
  const emailHtml = mailGenerator.generate(options.mailgenContent);

  const transporter = nodemailer.createTransport({
    host: process.env.MAILTRAP_SMTP_HOST,
    port: process.env.MAILTRAP_SMTP_PORT,
    auth: {
      user: process.env.MAILTRAP_SMTP_USER,
      pass: process.env.MAILTRAP_SMTP_PASS,
    },
  });

  const mail = {
    from: "mail.taskmanager@example.com",
    to: options.email,
    subject: options.subject,
    text: emailTextual,
    html: emailHtml,
  };

  try {
    await transporter.sendMail(mail);
    return true;
  } catch (error) {
    console.error(
      `Email Service failed siliently. This might be happend due to invalid mail credentials.`,
      error,
    );
    return false;
  }
};

const emailVerificationMailgenContent = (username, verificationUrl) => {
  return {
    body: {
      name: username,
      intro: "Weolcome to our App! We have excited to have you on board.",
      action: {
        instructions:
          "To verify your email, please click on the following button",
        button: {
          color: "#1A73E8",
          text: "Verify Email",
          link: verificationUrl,
        },
      },
    },
    outro:
      "If you need any help, please contact us at by just replying to this email",
  };
};

const forgotPasswordMailgenContent = (username, passwordResetUrl) => {
  return {
    body: {
      name: username,
      intro: "You requested to reset your password for your account.",
      action: {
        instructions:
          "To reset your password, please click on the following button",
        button: {
          color: "#1A73E8",
          text: "Reset Password",
          link: passwordResetUrl,
        },
      },
    },
    outro:
      "If you need any help, please contact us at by just replying to this email",
  };
};

export {
  emailVerificationMailgenContent,
  forgotPasswordMailgenContent,
  sendEmail,
};
