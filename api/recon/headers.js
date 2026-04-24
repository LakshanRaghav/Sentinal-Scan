import axios from 'axios';
import https from 'https';

const agent = new https.Agent({
  rejectUnauthorized: false
});

export default async (req, res) => {
  // CORS Headers
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
    const response = await axios.get(targetUrl, {
      timeout: 5000,
      httpsAgent: agent,
      validateStatus: () => true // Resolve on any status code
    });

    const headers = response.headers;
    const findings = [];

    // Security Headers Check
    const checkHeader = (name, required, severity, desc, missingDesc) => {
      const value = headers[name.toLowerCase()];
      if (value) {
        if (!required) {
          findings.push({ title: `${name} Present`, severity: 'BLUE', what_it_is: desc, why_dangerous: 'Informational', status_code: response.status });
        }
      } else if (required) {
        findings.push({ 
          title: `Missing ${name}`, 
          severity: severity, 
          what_it_is: missingDesc, 
          why_dangerous: desc, 
          fix_steps: [`Configure your web server or application framework to include the ${name} header in all responses.`]
        });
      }
    };

    checkHeader('Content-Security-Policy', true, 'YELLOW', 'Mitigates XSS and data injection attacks by restricting resource origins.', 'The Content-Security-Policy header is completely missing.');
    checkHeader('Strict-Transport-Security', targetUrl.startsWith('https'), 'YELLOW', 'Enforces secure (HTTP over SSL/TLS) connections to the server.', 'The HSTS header is missing, leaving the site vulnerable to downgrade attacks.');
    checkHeader('X-Frame-Options', true, 'BLUE', 'Protects against clickjacking attacks by controlling whether the site can be framed.', 'The X-Frame-Options header is missing.');
    checkHeader('X-Content-Type-Options', true, 'BLUE', 'Prevents MIME-sniffing attacks.', 'The X-Content-Type-Options header is missing.');
    checkHeader('Referrer-Policy', true, 'BLUE', 'Controls how much referrer information is included with requests.', 'The Referrer-Policy header is missing.');

    // Cookie Security Check
    const setCookie = headers['set-cookie'];
    if (setCookie) {
      setCookie.forEach(cookie => {
        if (!cookie.toLowerCase().includes('secure') && targetUrl.startsWith('https')) {
          findings.push({ title: 'Insecure Cookie', severity: 'YELLOW', what_it_is: 'A cookie is set without the Secure attribute.', why_dangerous: 'The cookie can be transmitted in cleartext over unencrypted HTTP connections.' });
        }
        if (!cookie.toLowerCase().includes('httponly')) {
          findings.push({ title: 'Missing HttpOnly Cookie', severity: 'YELLOW', what_it_is: 'A cookie is set without the HttpOnly attribute.', why_dangerous: 'The cookie can be accessed via client-side scripts, increasing XSS risk.' });
        }
        if (!cookie.toLowerCase().includes('samesite')) {
          findings.push({ title: 'Missing SameSite Cookie Attribute', severity: 'BLUE', what_it_is: 'A cookie is set without the SameSite attribute.', why_dangerous: 'This increases the risk of Cross-Site Request Forgery (CSRF) attacks.' });
        }
      });
    }

    // CORS Check
    const acao = headers['access-control-allow-origin'];
    if (acao === '*') {
      findings.push({ title: 'Overly Permissive CORS', severity: 'YELLOW', what_it_is: 'Access-Control-Allow-Origin is set to *', why_dangerous: 'Any external domain can read responses from this server via client-side scripts if not properly restricted by authentication.' });
    }

    return res.status(200).json({ success: true, findings, status: response.status });

  } catch (error) {
    return res.status(500).json({ error: `Header scan failed: ${error.message}` });
  }
};
