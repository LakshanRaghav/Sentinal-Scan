import https from 'https';

export default async (req, res) => {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { targetUrl } = req.body;
  if (!targetUrl) {
    return res.status(400).json({ error: 'targetUrl required' });
  }

  try {
    const urlObj = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
    if (urlObj.protocol !== 'https:') {
      return res.status(200).json({ 
        success: true, 
        findings: [{ title: 'No HTTPS', severity: 'RED', what_it_is: 'Target is not using HTTPS.', why_dangerous: 'All traffic is sent in cleartext.', fix_steps: ['Install an SSL/TLS certificate.'] }]
      });
    }

    const options = {
      host: urlObj.hostname,
      port: urlObj.port || 443,
      method: 'GET',
      rejectUnauthorized: false, // We want to inspect it even if invalid
    };

    const sslData = await new Promise((resolve, reject) => {
      const request = https.request(options, (response) => {
        const cert = response.socket.getPeerCertificate(true);
        const protocol = response.socket.getProtocol();
        resolve({ cert, protocol, authorized: response.socket.authorized, authError: response.socket.authorizationError });
      });

      request.on('error', reject);
      request.setTimeout(5000, () => {
        request.destroy();
        reject(new Error('Timeout'));
      });
      request.end();
    });

    const findings = [];
    const { cert, protocol, authorized, authError } = sslData;

    if (!authorized) {
      findings.push({ title: 'Invalid SSL Certificate', severity: 'RED', what_it_is: `Certificate is invalid: ${authError}`, why_dangerous: 'Users will see browser warnings. MITM attacks possible.', fix_steps: ['Renew or fix certificate installation.'] });
    }

    // Check expiry
    const validTo = new Date(cert.valid_to);
    const daysRemaining = (validTo - new Date()) / (1000 * 60 * 60 * 24);
    
    if (daysRemaining < 0) {
      findings.push({ title: 'Expired SSL Certificate', severity: 'RED', what_it_is: `Certificate expired on ${cert.valid_to}`, why_dangerous: 'Browsers will block access.', fix_steps: ['Renew the certificate immediately.'] });
    } else if (daysRemaining < 30) {
      findings.push({ title: 'SSL Expiring Soon', severity: 'YELLOW', what_it_is: `Certificate expires in ${Math.round(daysRemaining)} days.`, why_dangerous: 'Site will become inaccessible soon.', fix_steps: ['Renew the certificate.'] });
    }

    // Check Protocol
    if (protocol === 'TLSv1.0' || protocol === 'TLSv1.1') {
      findings.push({ title: 'Obsolete TLS Version', severity: 'RED', what_it_is: `Server is using ${protocol}.`, why_dangerous: 'Vulnerable to known attacks (e.g., POODLE, BEAST).', fix_steps: ['Disable TLS 1.0 and 1.1 on the server.'] });
    } else {
      findings.push({ title: 'Modern TLS Supported', severity: 'BLUE', what_it_is: `Server negotiated ${protocol}.`, why_dangerous: 'Informational' });
    }

    return res.status(200).json({ 
      success: true, 
      findings, 
      sslInfo: { 
        issuer: cert.issuer?.O || 'Unknown', 
        subject: cert.subject?.CN || 'Unknown', 
        validTo: cert.valid_to,
        protocol 
      } 
    });

  } catch (error) {
    return res.status(500).json({ error: `SSL scan failed: ${error.message}` });
  }
};
