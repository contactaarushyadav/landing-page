import crypto from 'crypto';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  // 1. SECURITY: Check if this message really came from Razorpay
  const signature = req.headers['x-razorpay-signature'];
  const expectedSignature = crypto
    .createHmac('sha256', process.env.RAZORPAY_SECRET)
    .update(JSON.stringify(req.body))
    .digest('hex');

  if (signature !== expectedSignature) {
    return res.status(400).json({ message: 'Invalid signature' });
  }

  const { event, payload } = req.body;

  // 2. Only trigger for successful payments
  if (event === 'payment.captured') {
    const payment = payload.payment.entity;

    // Helper: Hash sensitive data for Meta's privacy rules
    const hash = (val) => val ? crypto.createHash('sha256').update(val.toLowerCase().trim()).digest('hex') : null;

    try {
      // 3. Forward the data to Meta Conversions API (CAPI)
      await fetch(`https://graph.facebook.com/v29.0/${process.env.META_PIXEL_ID}/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          data: [{
            event_name: 'Purchase',
            event_time: Math.floor(Date.now() / 1000),
            action_source: 'website',
            event_id: payment.id, 
            user_data: {
              em: [hash(payment.email)],
              ph: [hash(payment.contact)],
            },
            custom_data: {
              currency: payment.currency,
              value: payment.amount / 100, 
            },
          }],
          access_token: process.env.META_ACCESS_TOKEN,
        }),
      });

      return res.status(200).json({ status: 'success' });
    } catch (err) {
      return res.status(500).json({ error: 'Meta signal failed' });
    }
  }

  res.status(200).json({ status: 'ignored' });
}
