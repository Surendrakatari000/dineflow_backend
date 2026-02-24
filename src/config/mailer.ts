import sgMail from "@sendgrid/mail";

sgMail.setApiKey(process.env.SENDGRID_API_KEY!);

/**
 * Sends a 6-digit OTP to the user's email via SendGrid.
 */
export const sendOTPEmail = async (
  email: string,
  otp: number,
): Promise<void> => {
  const message = {
    to: email,
    from: process.env.EMAIL_USER!, // Ensure this is a verified sender in SendGrid
    subject: "Email Verification",
    html: `
            <div style="font-family: sans-serif; padding: 20px; border: 1px solid #eee; border-radius: 5px;">
                <h2 style="color: #333;">Email Verification</h2>
                <p style="font-size: 16px;">Your OTP Code:</p>
                <h1 style="color: #007bff; letter-spacing: 5px;">${otp}</h1>
                <p style="color: #666; font-size: 14px;">This code is valid for <strong>1 minute</strong>.</p>
                <hr style="border:none; border-top: 1px solid #eee;" />
                <p style="font-size: 12px; color: #999;">If you did not request this, please ignore this email.</p>
            </div>
        `,
  };

  try {
    await sgMail.send(message);
  } catch (error) {
    console.error("SendGrid Mail Error:", error);
    throw new Error("Failed to send OTP email.");
  }
};
