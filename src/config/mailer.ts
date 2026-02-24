import sgMail from "@sendgrid/mail";

sgMail.setApiKey(process.env.SENDGRID_API_KEY!);

export const sendOTPEmail = async (
  email: string,
  otp: number,
): Promise<void> => {
  const message = {
    to: email,
    from: process.env.EMAIL_USER!,
    subject: "Email Verification",
    html: `
      <div style="font-family: sans-serif; padding: 20px; border: 1px solid #eee; border-radius: 5px;">
          <h2 style="color: #333;">Verification Code</h2>
          <p style="font-size: 16px;">Use the following code to complete your request:</p>
          <h1 style="color: #007bff; letter-spacing: 5px; font-size: 32px;">${otp}</h1>
          <p style="color: #666; font-size: 14px;">This code is valid for <strong>5 minutes</strong>.</p> <hr style="border:none; border-top: 1px solid #eee;" />
          <p style="font-size: 12px; color: #999;">If you did not request this code, please secure your account.</p>
      </div>
    `,
  };

  try {
    await sgMail.send(message);
  } catch (error: unknown) {
    const err = error as any; // Cast locally to access SendGrid properties
    console.error("SendGrid Detailed Error:", err.response?.body || err);
    throw error;
  }
};
