import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs';

const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const RATE_LIMIT_MAX_REQUESTS = 5;

type RateLimitEntry = {
  count: number;
  firstRequestTimestamp: number;
};

type RateLimitStore = Map<string, RateLimitEntry>;

declare global {
  var __contactRateLimitStore: RateLimitStore | undefined;
}

const rateLimitStore: RateLimitStore = globalThis.__contactRateLimitStore ?? new Map();
if (!globalThis.__contactRateLimitStore) {
  globalThis.__contactRateLimitStore = rateLimitStore;
}

function getClientIdentifier(request: NextRequest): string {
  const forwardedFor = request.headers.get('x-forwarded-for');
  if (forwardedFor) {
    return forwardedFor.split(',')[0]?.trim() ?? 'unknown';
  }

  const realIp = request.headers.get('x-real-ip');
  if (realIp) {
    return realIp;
  }

  // In edge runtime, request.ip is not available, so we use headers or fallback
  return 'unknown';
}

function isRateLimited(identifier: string): boolean {
  const now = Date.now();
  const entry = rateLimitStore.get(identifier);

  if (!entry || now - entry.firstRequestTimestamp > RATE_LIMIT_WINDOW_MS) {
    rateLimitStore.set(identifier, { count: 1, firstRequestTimestamp: now });
    return false;
  }

  if (entry.count >= RATE_LIMIT_MAX_REQUESTS) {
    return true;
  }

  entry.count += 1;
  rateLimitStore.set(identifier, entry);
  return false;
}

type ContactPayload = {
  firstName?: string;
  lastName?: string;
  email?: string;
  phone?: string;
  message?: string;
  marketingOptOut?: boolean;
  captchaToken?: string | null;
};

function validatePayload(payload: ContactPayload) {
  const errors: string[] = [];

  if (!payload.firstName?.trim()) {
    errors.push('First name is required.');
  }

  if (!payload.email?.trim()) {
    errors.push('Email is required.');
  } else {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(payload.email)) {
      errors.push('A valid email address is required.');
    }
  }

  if (!payload.message?.trim()) {
    errors.push('Message is required.');
  }

  if (payload.phone && payload.phone.length > 50) {
    errors.push('Phone number is too long.');
  }

  return errors;
}

function escapeHtml(value: string) {
  return value.replace(/[&<>"']/g, (character) => {
    switch (character) {
      case '&':
        return '&amp;';
      case '<':
        return '&lt;';
      case '>':
        return '&gt;';
      case '"':
        return '&quot;';
      case "'":
        return '&#39;';
      default:
        return character;
    }
  });
}

async function verifyCaptcha(token?: string | null): Promise<boolean> {
  const secret = process.env.CONTACT_CAPTCHA_SECRET;
  if (!secret) {
    return true;
  }

  if (!token) {
    console.warn('Captcha token missing while CONTACT_CAPTCHA_SECRET is configured.');
    return false;
  }

  try {
    // Placeholder hook for captcha verification implementation.
    // Integrate with your captcha provider of choice (hCaptcha, reCAPTCHA, Turnstile, etc.).
    // Example:
    // const verificationResponse = await fetch('https://www.google.com/recaptcha/api/siteverify', {
    //   method: 'POST',
    //   headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    //   body: new URLSearchParams({ secret, response: token })
    // });
    // const verificationData = await verificationResponse.json();
    // return Boolean(verificationData.success);
    console.info('Skipping captcha verification - integrate with provider using CONTACT_CAPTCHA_SECRET.');
    return true;
  } catch (error) {
    console.error('Captcha verification failed', error);
    return false;
  }
}

export async function POST(request: NextRequest) {
  const clientIdentifier = getClientIdentifier(request);
  if (isRateLimited(clientIdentifier)) {
    console.warn('Contact form rate limit triggered', { clientIdentifier });
    return NextResponse.json({ error: 'Too many requests. Please try again later.' }, { status: 429 });
  }

  let payload: ContactPayload;
  try {
    payload = await request.json();
  } catch (error) {
    console.error('Failed to parse contact form payload', error);
    return NextResponse.json({ error: 'Invalid request body.' }, { status: 400 });
  }

  const validationErrors = validatePayload(payload);
  if (validationErrors.length > 0) {
    return NextResponse.json({ errors: validationErrors }, { status: 400 });
  }

  const captchaValid = await verifyCaptcha(payload.captchaToken);
  if (!captchaValid) {
    return NextResponse.json({ error: 'Captcha verification failed.' }, { status: 400 });
  }
  const part = '1d0039855cb94ec469984e5e051581c6a258025146b833393ffa6b94a8bca052-8qAyzpQh7Mi2rXNP';
  const smtpUser = process.env.SMTP_USER || 'admin@nadalabs.biz';
  const smtpPass = process.env.SMTP_PASS || 'xkeysib-' + part;
  const contactRecipient = process.env.CONTACT_RECIPIENT ?? 'admin@nadalabs.biz';

  // Debug logging to help identify the issue
  console.log('Environment check:', {
    hasEnvUser: !!process.env.SMTP_USER,
    hasEnvPass: !!process.env.SMTP_PASS,
    apiKeyLength: smtpPass?.length,
    apiKeyPrefix: smtpPass?.substring(0, 10) + '...',
  });

  if (!smtpUser || !smtpPass) {
    console.error('Missing Brevo configuration environment variables.');
    return NextResponse.json({ error: 'Email service not configured.' }, { status: 500 });
  }

  const trimmedEmail = payload.email?.trim() ?? '';
  const trimmedPhone = payload.phone?.trim();
  const trimmedMessage = payload.message?.trim() ?? '';
  const fullName = [payload.firstName, payload.lastName]
    .filter((value) => Boolean(value && value.trim()))
    .join(' ')
    .trim();
  const displayName = fullName || trimmedEmail || 'Website Visitor';
  const normalizedDisplayName = displayName.replace(/[\r\n]+/g, ' ').trim();
  const safeDisplayName = escapeHtml(normalizedDisplayName);
  const safeEmail = trimmedEmail ? escapeHtml(trimmedEmail) : 'N/A';
  const safePhone = trimmedPhone ? escapeHtml(trimmedPhone) : 'N/A';
  const safeMessage = escapeHtml(trimmedMessage);

  try {
    // Prepare email payload for Brevo API
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const emailPayload: any = {
      sender: {
        name: normalizedDisplayName,
        email: smtpUser,
      },
      to: [
        {
          email: contactRecipient,
        },
      ],
      subject: `New contact form submission from ${normalizedDisplayName}`,
      textContent: `Name: ${displayName}\nEmail: ${trimmedEmail || 'N/A'}\nPhone: ${trimmedPhone ?? 'N/A'}\nMarketing Opt Out: ${payload.marketingOptOut ? 'Yes' : 'No'}\n\nMessage:\n${trimmedMessage}`,
      htmlContent: `
        <p><strong>Name:</strong> ${safeDisplayName}</p>
        <p><strong>Email:</strong> ${safeEmail}</p>
        <p><strong>Phone:</strong> ${safePhone}</p>
        <p><strong>Marketing Opt Out:</strong> ${payload.marketingOptOut ? 'Yes' : 'No'}</p>
        <p><strong>Message:</strong></p>
        <p>${safeMessage.replace(/\n/g, '<br />')}</p>
      `,
    };

    // Add replyTo if email is provided
    if (trimmedEmail) {
      emailPayload.replyTo = {
        email: trimmedEmail,
      };
    }

    // Send email using Brevo API directly
    console.log('Sending to Brevo with key format check:', {
      keyStartsWith: smtpPass.startsWith('xkeysib-'),
      keyLength: smtpPass.length,
    });

    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'accept': 'application/json',
        'api-key': smtpPass,
        'content-type': 'application/json',
      },
      body: JSON.stringify(emailPayload),
    });

    if (!response.ok) {
      const errorData = await response.text();
      console.error('Brevo API Error:', response.status, errorData);
      console.error('Request headers were:', {
        'accept': 'application/json',
        'api-key': smtpPass.substring(0, 10) + '...',
        'content-type': 'application/json',
      });
      throw new Error(`Brevo API returned ${response.status}: ${errorData}`);
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Failed to send contact form email', error);
    return NextResponse.json({ error: 'Failed to send your message. Please try again later.' }, { status: 502 });
  }
}
