import { Env } from "./types";

interface SendEmailOptions {
  to: string;
  replyTo: string;
  subject: string;
  name: string;
  email: string;
  message: string;
  extraFields: Record<string, string>;
}

/**
 * Send a form submission email via Resend SDK.
 * Uses dynamic import to work in the Workers environment.
 */
export async function sendFormEmail(
  env: Env,
  opts: SendEmailOptions
): Promise<void> {
  const { Resend } = await import("resend");
  const resend = new Resend(env.RESEND_API_KEY);

  const { error } = await resend.emails.send({
    from: env.FROM_EMAIL,
    to: opts.to,
    reply_to: opts.replyTo,
    subject: opts.subject,
    html: buildEmailHtml(opts),
  });

  if (error) {
    throw new Error(`Resend error: ${error.message}`);
  }
}

function capitalize(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1).replace(/_/g, " ");
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function buildEmailHtml(opts: SendEmailOptions): string {
  const extraRows = Object.entries(opts.extraFields)
    .filter(([, v]) => v && typeof v === "string")
    .map(
      ([k, v]) => `
      <tr>
        <td style="padding:8px 12px;background:#f9f9f9;font-weight:600;width:140px;border-bottom:1px solid #eee;">${escapeHtml(capitalize(k))}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #eee;">${escapeHtml(v)}</td>
      </tr>`
    )
    .join("");

  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="font-family:sans-serif;color:#333;max-width:600px;margin:auto;padding:20px;">
  <div style="border-left:4px solid #C5A059;padding-left:16px;margin-bottom:24px;">
    <h2 style="margin:0;color:#C5A059;">${escapeHtml(opts.subject)}</h2>
  </div>
  <table style="width:100%;border-collapse:collapse;font-size:15px;">
    <tr>
      <td style="padding:8px 12px;background:#f9f9f9;font-weight:600;width:140px;border-bottom:1px solid #eee;">Name</td>
      <td style="padding:8px 12px;border-bottom:1px solid #eee;">${escapeHtml(opts.name)}</td>
    </tr>
    <tr>
      <td style="padding:8px 12px;background:#f9f9f9;font-weight:600;border-bottom:1px solid #eee;">Reply To</td>
      <td style="padding:8px 12px;border-bottom:1px solid #eee;"><a href="mailto:${escapeHtml(opts.email)}">${escapeHtml(opts.email)}</a></td>
    </tr>
    ${extraRows}
    <tr>
      <td style="padding:8px 12px;background:#f9f9f9;font-weight:600;vertical-align:top;border-bottom:1px solid #eee;">Message</td>
      <td style="padding:8px 12px;border-bottom:1px solid #eee;white-space:pre-line;">${escapeHtml(opts.message)}</td>
    </tr>
  </table>
  <p style="margin-top:24px;font-size:12px;color:#999;">
    Sent via <a href="https://formsend.ezeroandone.io" style="color:#C5A059;">FormSend</a>
  </p>
</body>
</html>`;
}
