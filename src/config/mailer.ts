import sgMail from "@sendgrid/mail";
import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

type Provider = "sendgrid" | "smtp";

const sendgridApiKey = process.env.SENDGRID_API_KEY;
const sendgridFrom = process.env.SENDGRID_FROM_EMAIL || process.env.EMAIL_USER;

if (sendgridApiKey) {
  sgMail.setApiKey(sendgridApiKey);
}

const smtpHost = process.env.SMTP_HOST;
const smtpPort = Number(process.env.SMTP_PORT || "587");
const smtpUser = process.env.SMTP_USER;
const smtpPass = process.env.SMTP_PASS;
const smtpFrom = process.env.SMTP_FROM_EMAIL || process.env.EMAIL_USER;

/**
 * MODERN & BEAUTIFUL EMAIL TEMPLATE FOR FUDX
 */
const getEmailTemplate = (otp: number) => {
  return `
    <div style="background-color: #f9fafb; padding: 40px 20px; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;">
      <div style="max-width: 500px; margin: 0 auto; background-color: #ffffff; border-radius: 20px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.05); border: 1px solid #e5e7eb;">
        
        <div style="background-color: #ffffff; padding: 30px; text-align: center; border-bottom: 1px solid #f3f4f6;">
          <img src="https://res.cloudinary.com/dz39z2hyf/image/upload/v1772089645/logo_qyhpej.png" 
               alt="FUDX Logo" 
               style="width: 180px; height: auto; display: block; margin: 0 auto;" />
        </div>

        <div style="padding: 40px 30px; text-align: center;">
          <h2 style="color: #111827; margin-bottom: 12px; font-size: 24px; font-weight: 700;">Verify your account</h2>
          <p style="color: #4b5563; font-size: 16px; line-height: 1.6; margin-bottom: 30px;">
            To complete your request, please use the 6-digit verification code below. This code is valid for <b>5 minutes</b>.
          </p>
          
          <div style="margin-bottom: 30px;">
            <div style="display: inline-block; background-color: #fef2f2; color: #dc2626; font-size: 38px; font-weight: 800; letter-spacing: 10px; padding: 20px 40px; border-radius: 16px; border: 2px solid #fee2e2;">
              ${otp}
            </div>
          </div>

          <p style="color: #9ca3af; font-size: 13px; line-height: 1.4;">
            If you did not request this code, no further action is required. Your account remains secure.
          </p>
        </div>

        <div style="background-color: #f9fafb; padding: 25px; text-align: center; border-top: 1px solid #f3f4f6;">
          <p style="color: #6b7280; font-size: 12px; margin: 0; font-weight: 500;">
            Delivering Happiness
          </p>
          <p style="color: #9ca3af; font-size: 11px; margin-top: 8px;">
            &copy; 2026 FUDX Inc. Mumbai, India.
          </p>
        </div>
      </div>
    </div>
  `;
};

const getPreferredProvider = (): Provider | null => {
  if (sendgridApiKey && sendgridFrom) return "sendgrid";
  if (smtpHost && smtpUser && smtpPass && smtpFrom) return "smtp";
  return null;
};

const sendViaSendGrid = async (email: string, otp: number): Promise<void> => {
  console.log(`[MAILER] Attempting SendGrid delivery to: ${email}`);
  await sgMail.send({
    to: email,
    from: sendgridFrom!,
    subject: `Your FUDX Verification Code: ${otp}`,
    html: getEmailTemplate(otp),
  });
};

const sendViaSMTP = async (email: string, otp: number): Promise<void> => {
  console.log(`[MAILER] Attempting SMTP delivery to: ${email}`);
  const transporter = nodemailer.createTransport({
    host: smtpHost,
    port: smtpPort,
    secure: smtpPort === 465,
    auth: { user: smtpUser, pass: smtpPass },
  });

  await transporter.sendMail({
    from: `"FUDX Support" <${smtpFrom}>`,
    to: email,
    subject: `Your FUDX Verification Code: ${otp}`,
    html: getEmailTemplate(otp),
  });
};

export const sendOTPEmail = async (
  email: string,
  otp: number,
): Promise<void> => {
  const provider = getPreferredProvider();

  if (!provider) {
    throw new Error("No email provider configured in .env");
  }

  try {
    if (provider === "sendgrid") {
      await sendViaSendGrid(email, otp);
    } else {
      await sendViaSMTP(email, otp);
    }
    console.log(`[MAILER] Success: OTP sent to ${email} via ${provider}`);
  } catch (error) {
    console.error(`[MAILER] Primary provider (${provider}) failed.`);

    if (provider === "sendgrid" && smtpHost) {
      console.log("[MAILER] Starting SMTP fallback...");
      try {
        await sendViaSMTP(email, otp);
        console.log(`[MAILER] Success: OTP sent to ${email} via SMTP Fallback`);
      } catch (fallbackError) {
        console.error("[MAILER] Fallback also failed.");
        throw fallbackError;
      }
    } else {
      throw error;
    }
  }
};



// import sgMail from "@sendgrid/mail";
// import nodemailer from "nodemailer";
// import dotenv from "dotenv";

// dotenv.config();

// type Provider = "sendgrid" | "smtp";

// const sendgridApiKey = process.env.SENDGRID_API_KEY;
// const sendgridFrom = process.env.SENDGRID_FROM_EMAIL || process.env.EMAIL_USER;

// if (sendgridApiKey) {
//   sgMail.setApiKey(sendgridApiKey);
// }

// const smtpHost = process.env.SMTP_HOST;
// const smtpPort = Number(process.env.SMTP_PORT || "587");
// const smtpUser = process.env.SMTP_USER;
// const smtpPass = process.env.SMTP_PASS;
// const smtpFrom = process.env.SMTP_FROM_EMAIL || process.env.EMAIL_USER;

// /**
//  * MODERN & BEAUTIFUL EMAIL TEMPLATE
//  */
// const getEmailTemplate = (otp: number) => {
//   return `
//     <div style="background-color: #f4f4f7; padding: 40px 20px; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;">
//       <div style="max-width: 500px; margin: 0 auto; background-color: #ffffff; border-radius: 16px; overflow: hidden; shadow: 0 4px 12px rgba(0,0,0,0.05); border: 1px solid #e1e1e8;">

//         <div style="background-color: #000000; padding: 30px; text-align: center;">
//           <h1 style="color: #ffffff; margin: 0; font-size: 24px; letter-spacing: 1px;">BookHub</h1>
//         </div>

//         <div style="padding: 40px 30px; text-align: center;">
//           <h2 style="color: #1a1a1a; margin-bottom: 10px; font-size: 22px;">Verify your email</h2>
//           <p style="color: #666666; font-size: 16px; line-height: 1.5;">
//             Use the verification code below to access your account. This code will expire in <b>5 minutes</b>.
//           </p>

//           <div style="margin: 30px 0;">
//             <span style="display: inline-block; background-color: #f1f5f9; color: #000000; font-size: 36px; font-weight: 700; letter-spacing: 8px; padding: 15px 30px; border-radius: 12px; border: 1px dashed #cbd5e1;">
//               ${otp}
//             </span>
//           </div>

//           <p style="color: #94a3b8; font-size: 13px;">
//             If you didn't request this code, you can safely ignore this email.
//           </p>
//         </div>

//         <div style="background-color: #f8fafc; padding: 20px; text-align: center; border-top: 1px solid #e2e8f0;">
//           <p style="color: #64748b; font-size: 12px; margin: 0;">
//             &copy; 2026 BookHub Inc. Mumbai, India.
//           </p>
//         </div>
//       </div>
//     </div>
//   `;
// };

// const getPreferredProvider = (): Provider | null => {
//   if (sendgridApiKey && sendgridFrom) return "sendgrid";
//   if (smtpHost && smtpUser && smtpPass && smtpFrom) return "smtp";
//   return null;
// };

// const sendViaSendGrid = async (email: string, otp: number): Promise<void> => {
//   console.log(`[MAILER] Attempting SendGrid delivery to: ${email}`);
//   await sgMail.send({
//     to: email,
//     from: sendgridFrom!,
//     subject: `Your Verification Code: ${otp}`,
//     html: getEmailTemplate(otp),
//   });
// };

// const sendViaSMTP = async (email: string, otp: number): Promise<void> => {
//   console.log(`[MAILER] Attempting SMTP delivery to: ${email}`);
//   const transporter = nodemailer.createTransport({
//     host: smtpHost,
//     port: smtpPort,
//     secure: smtpPort === 465,
//     auth: { user: smtpUser, pass: smtpPass },
//   });

//   await transporter.sendMail({
//     from: `"BookHub Support" <${smtpFrom}>`,
//     to: email,
//     subject: `Your Verification Code: ${otp}`,
//     html: getEmailTemplate(otp),
//   });
// };

// export const sendOTPEmail = async (
//   email: string,
//   otp: number,
// ): Promise<void> => {
//   const provider = getPreferredProvider();

//   if (!provider) {
//     throw new Error("No email provider configured in .env");
//   }

//   try {
//     if (provider === "sendgrid") {
//       await sendViaSendGrid(email, otp);
//     } else {
//       await sendViaSMTP(email, otp);
//     }
//     console.log(`[MAILER] Success: OTP sent to ${email} via ${provider}`);
//   } catch (error) {
//     console.error(`[MAILER] Primary provider (${provider}) failed.`);

//     if (provider === "sendgrid" && smtpHost) {
//       console.log("[MAILER] Starting SMTP fallback...");
//       try {
//         await sendViaSMTP(email, otp);
//         console.log(`[MAILER] Success: OTP sent to ${email} via SMTP Fallback`);
//       } catch (fallbackError) {
//         console.error("[MAILER] Fallback also failed.");
//         throw fallbackError;
//       }
//     } else {
//       throw error;
//     }
//   }
// };

// import sgMail from "@sendgrid/mail";
// import nodemailer from "nodemailer";
// import dotenv from "dotenv";

// dotenv.config();

// type Provider = "sendgrid" | "smtp";

// const sendgridApiKey = process.env.SENDGRID_API_KEY;
// const sendgridFrom = process.env.SENDGRID_FROM_EMAIL || process.env.EMAIL_USER;

// if (sendgridApiKey) {
//   sgMail.setApiKey(sendgridApiKey);
// }

// const smtpHost = process.env.SMTP_HOST;
// const smtpPort = Number(process.env.SMTP_PORT || "587");
// const smtpUser = process.env.SMTP_USER;
// const smtpPass = process.env.SMTP_PASS;
// const smtpFrom = process.env.SMTP_FROM_EMAIL || process.env.EMAIL_USER;

// /*
// COMMON EMAIL TEMPLATE
// */
// const getEmailTemplate = (otp: number, provider: string) => {
//   return `
//     <div style="font-family: sans-serif; padding: 20px; border: 1px solid #eee; border-radius: 5px;">
//         <h2>Verification Code</h2>

//         <p>Use this OTP:</p>

//         <h1>${otp}</h1>

//         <p>Valid for 5 minutes</p>

//         <hr/>

//         <p style="color:gray;">
//         Sent via <b>${provider}</b>
//         </p>

//     </div>
//   `;
// };

// const getPreferredProvider = (): Provider | null => {
//   if (sendgridApiKey && sendgridFrom) return "sendgrid";
//   if (smtpHost && smtpUser && smtpPass && smtpFrom) return "smtp";
//   return null;
// };

// const sendViaSendGrid = async (email: string, otp: number): Promise<void> => {
//   const [response] = await sgMail.send({
//     to: email,

//     from: sendgridFrom!,

//     subject: "Email Verification",

//     html: getEmailTemplate(otp, "SendGrid"),
//   });

//   console.log("SendGrid status:", response.statusCode);
// };

// const sendViaSMTP = async (email: string, otp: number): Promise<void> => {
//   const transporter = nodemailer.createTransport({
//     host: smtpHost,

//     port: smtpPort,

//     secure: smtpPort === 465,

//     auth: {
//       user: smtpUser,

//       pass: smtpPass,
//     },
//   });

//   const info = await transporter.sendMail({
//     from: smtpFrom,

//     to: email,

//     subject: "Email Verification",

//     html: getEmailTemplate(otp, "SMTP"),
//   });

//   console.log("SMTP messageId:", info.messageId);
// };

// export const sendOTPEmail = async (
//   email: string,
//   otp: number,
// ): Promise<void> => {
//   const provider = getPreferredProvider();

//   if (!provider) {
//     throw new Error("No provider configured");
//   }

//   try {
//     if (provider === "sendgrid") {
//       await sendViaSendGrid(email, otp);
//     } else {
//       await sendViaSMTP(email, otp);
//     }
//   } catch (error) {
//     console.log("Main provider failed");

//     if (provider === "sendgrid") {
//       console.log("Trying SMTP fallback");

//       await sendViaSMTP(email, otp);
//     } else {
//       throw error;
//     }
//   }
// };

// import sgMail from "@sendgrid/mail";
// import nodemailer from "nodemailer";
// import dotenv from "dotenv";

// dotenv.config();

// type Provider = "sendgrid" | "smtp";

// const sendgridApiKey = process.env.SENDGRID_API_KEY;
// const sendgridFrom = process.env.SENDGRID_FROM_EMAIL || process.env.EMAIL_USER;

// if (sendgridApiKey) {
//   sgMail.setApiKey(sendgridApiKey);
// }

// const smtpHost = process.env.SMTP_HOST;
// const smtpPort = Number(process.env.SMTP_PORT || "587");
// const smtpUser = process.env.SMTP_USER;
// const smtpPass = process.env.SMTP_PASS;
// const smtpFrom = process.env.SMTP_FROM_EMAIL || process.env.EMAIL_USER;

// const getPreferredProvider = (): Provider | null => {
//   if (sendgridApiKey && sendgridFrom) return "sendgrid";
//   if (smtpHost && smtpUser && smtpPass && smtpFrom) return "smtp";
//   return null;
// };

// const sendViaSendGrid = async (email: string, otp: number): Promise<void> => {
//   if (!sendgridApiKey || !sendgridFrom) {
//     throw new Error(
//       "SendGrid not configured: missing SENDGRID_API_KEY or SENDGRID_FROM_EMAIL/EMAIL_USER",
//     );
//   }

//   const [response] = await sgMail.send({
//     to: email,
//     from: sendgridFrom,
//     subject: "Email Verification",
//     html: `
//       <div style="font-family: sans-serif; padding: 20px; border: 1px solid #eee; border-radius: 5px;">
//           <h2 style="color: #333;">Verification Code</h2>
//           <p style="font-size: 16px;">Use the following code to complete your request:</p>
//           <h1 style="color: #007bff; letter-spacing: 5px; font-size: 32px;">${otp}</h1>
//           <p style="color: #666; font-size: 14px;">This code is valid for <strong>5 minutes</strong>.</p> <hr style="border:none; border-top: 1px solid #eee;" />
//           <p style="font-size: 12px; color: #999;">If you did not request this code, please secure your account.</p>
//       </div>
//     `,
//   });
//   console.log(
//     `[MAILER][SENDGRID] Accepted status=${response.statusCode} to=${email}`,
//   );
// };

// const sendViaSMTP = async (email: string, otp: number): Promise<void> => {
//   if (!smtpHost || !smtpUser || !smtpPass || !smtpFrom) {
//     throw new Error(
//       "SMTP not configured: missing SMTP_HOST/SMTP_USER/SMTP_PASS/SMTP_FROM_EMAIL (or EMAIL_USER)",
//     );
//   }

//   const transporter = nodemailer.createTransport({
//     host: smtpHost,
//     port: smtpPort,
//     secure: smtpPort === 465,
//     auth: { user: smtpUser, pass: smtpPass },
//   });

//   const info = await transporter.sendMail({
//     from: smtpFrom,
//     to: email,
//     subject: "Email Verification",
//     html: `
//       <div style="font-family: sans-serif; padding: 20px; border: 1px solid #eee; border-radius: 5px;">
//           <h2 style="color: #333;">Verification Code</h2>
//           <p style="font-size: 16px;">Use the following code to complete your request:</p>
//           <h1 style="color: #007bff; letter-spacing: 5px; font-size: 32px;">${otp}</h1>
//           <p style="color: #666; font-size: 14px;">This code is valid for <strong>5 minutes</strong>.</p>
//           <hr style="border:none; border-top: 1px solid #eee;" />
//           <p style="font-size: 12px; color: #999;">If you did not request this code, please secure your account.</p>
//       </div>
//     `,
//   });
//   console.log(
//     `[MAILER][SMTP] Accepted messageId=${info.messageId} to=${email}`,
//   );
// };

// export const sendOTPEmail = async (
//   email: string,
//   otp: number,
// ): Promise<void> => {
//   const provider = getPreferredProvider();
//   if (!provider) {
//     throw new Error(
//       "No email provider configured. Configure SendGrid or SMTP credentials in .env",
//     );
//   }

//   try {
//     if (provider === "sendgrid") {
//       await sendViaSendGrid(email, otp);
//     } else {
//       await sendViaSMTP(email, otp);
//     }
//   } catch (error: unknown) {
//     const err = error as any;
//     const providerLabel = provider.toUpperCase();
//     const providerDetail =
//       err?.response?.body || err?.response?.data || err?.message || err;

//     console.error(`[MAILER][${providerLabel}] Delivery error:`, providerDetail);

//     if (
//       provider === "sendgrid" &&
//       smtpHost &&
//       smtpUser &&
//       smtpPass &&
//       smtpFrom
//     ) {
//       try {
//         console.warn("[MAILER] SendGrid failed, attempting SMTP fallback...");
//         await sendViaSMTP(email, otp);
//         return;
//       } catch (smtpError) {
//         console.error("[MAILER][SMTP] Fallback also failed:", smtpError);
//       }
//     }

//     throw new Error(
//       `OTP email failed via ${providerLabel}. Check provider credentials, sender verification, and account status.`,
//     );
//   }
// };

// import sgMail from "@sendgrid/mail";

// sgMail.setApiKey(process.env.SENDGRID_API_KEY!);

// export const sendOTPEmail = async (
//   email: string,
//   otp: number,
// ): Promise<void> => {
//   const message = {
//     to: email,
//     from: process.env.EMAIL_USER!,
//     subject: "Email Verification",
//     html: `
//       <div style="font-family: sans-serif; padding: 20px; border: 1px solid #eee; border-radius: 5px;">
//           <h2 style="color: #333;">Verification Code</h2>
//           <p style="font-size: 16px;">Use the following code to complete your request:</p>
//           <h1 style="color: #007bff; letter-spacing: 5px; font-size: 32px;">${otp}</h1>
//           <p style="color: #666; font-size: 14px;">This code is valid for <strong>5 minutes</strong>.</p> <hr style="border:none; border-top: 1px solid #eee;" />
//           <p style="font-size: 12px; color: #999;">If you did not request this code, please secure your account.</p>
//       </div>
//     `,
//   };

//   try {
//     await sgMail.send(message);
//     console.log(`OTP email sent to ${email}`);
//   } catch (error: unknown) {
//     const err = error as any; // Cast locally to access SendGrid properties
//     console.error("SendGrid Detailed Error:", err.response?.body || err);
//     throw error;
//   }
// };
