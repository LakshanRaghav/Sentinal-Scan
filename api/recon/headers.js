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

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { targetUrl } = req.body;
  if (!targetUrl) return res.status(400).json({ error: 'targetUrl required' });

  try {
    const response = await axios.get(targetUrl, {
      timeout: 5000,
      httpsAgent: agent,
      validateStatus: () => true
    });

    const headers = response.headers;
    const findings = [];

    // Security Headers Check
    const checkHeader = (name, required, missingSeverity, desc, missingDesc) => {
      const value = headers[name.toLowerCase()];
      if (value) {
        if (!required) {
          findings.push({ title: `${name} Present`, severity: 'BLUE', what_it_is: desc, why_dangerous: 'Informational', status_code: response.status });
        }
      } else if (required) {
        findings.push({ 
          title: `Missing ${name}`, 
          severity: missingSeverity, 
          what_it_is: missingDesc, 
          why_dangerous: desc, 
          fix_steps: [`Configure your web server or application framework to include the ${name} header in all responses.`]
        });
      }
    };

    // CSP Deep Parsing
    const csp = headers['content-security-policy'];
    if (csp) {
      const directives = csp.split(';');
      directives.forEach(dir => {
        const parts = dir.trim().split(' ');
        const name = parts[0];
        
        if (dir.includes("'unsafe-inline'") && (name === 'default-src' || name === 'script-src' || name === 'style-src')) {
          findings.push({ type: 'csp_unsafe_inline', title: 'CSP: Unsafe Inline Allowed', severity: 'YELLOW', what_it_is: `CSP contains 'unsafe-inline' in ${name}`, why_dangerous: 'Allows execution of inline scripts/styles, negating XSS protection.', fix_steps: ['Remove \'unsafe-inline\' and use nonces or hashes.'] });
        }
        if (dir.includes("'unsafe-eval'") && (name === 'default-src' || name === 'script-src')) {
          findings.push({ type: 'csp_unsafe_eval', title: 'CSP: Unsafe Eval Allowed', severity: 'YELLOW', what_it_is: `CSP contains 'unsafe-eval' in ${name}`, why_dangerous: 'Allows eval() which can be exploited for XSS.', fix_steps: ['Remove \'unsafe-eval\' and rewrite code to not use eval().'] });
        }
        if (parts.includes('*') && (name === 'default-src' || name === 'script-src')) {
          findings.push({ type: 'csp_wildcard_source', title: 'CSP: Wildcard Source', severity: 'YELLOW', what_it_is: `CSP contains * wildcard in ${name}`, why_dangerous: 'Allows loading resources from any domain.', fix_steps: ['Specify exact trusted domains instead of *'] });
        }
        if (dir.includes("data:") && (name === 'default-src' || name === 'script-src')) {
          findings.push({ type: 'csp_data_uri_scripts', title: 'CSP: Data URIs Allowed', severity: 'YELLOW', what_it_is: `CSP contains data: in ${name}`, why_dangerous: 'Allows execution of scripts from data URIs, which attackers can inject.', fix_steps: ['Remove data: from script/default sources.'] });
        }
      });
    } else {
      findings.push({ title: 'Missing Content-Security-Policy', severity: 'YELLOW', what_it_is: 'The Content-Security-Policy header is completely missing.', why_dangerous: 'Mitigates XSS and data injection attacks by restricting resource origins.', fix_steps: ['Implement a strict CSP.'] });
    }

    // HSTS Parse
    const hsts = headers['strict-transport-security'];
    if (hsts) {
      const match = hsts.match(/max-age=(\d+)/);
      if (match) {
        const age = parseInt(match[1], 10);
        if (age < 31536000) {
          findings.push({ title: 'HSTS Max-Age Too Low', severity: 'YELLOW', what_it_is: `HSTS max-age is ${age} seconds.`, why_dangerous: 'HSTS max-age should be at least 1 year (31536000).', fix_steps: ['Increase HSTS max-age to 31536000 or greater.'] });
        }
      }
    } else if (targetUrl.startsWith('https')) {
      findings.push({ title: 'Missing Strict-Transport-Security', severity: 'YELLOW', what_it_is: 'The HSTS header is missing.', why_dangerous: 'Leaves the site vulnerable to downgrade attacks.', fix_steps: ['Add HSTS header.'] });
    }

    // Permissions Policy
    checkHeader('Permissions-Policy', true, 'BLUE', 'Controls access to browser features (camera, mic).', 'The Permissions-Policy header is missing.');

    checkHeader('X-Frame-Options', true, 'BLUE', 'Protects against clickjacking attacks by controlling whether the site can be framed.', 'The X-Frame-Options header is missing.');
    checkHeader('X-Content-Type-Options', true, 'BLUE', 'Prevents MIME-sniffing attacks.', 'The X-Content-Type-Options header is missing.');
    checkHeader('Referrer-Policy', true, 'BLUE', 'Controls how much referrer information is included with requests.', 'The Referrer-Policy header is missing.');

    // Cookie Security Check
    const setCookie = headers['set-cookie'];
    if (setCookie) {
      setCookie.forEach(cookie => {
        if (!cookie.toLowerCase().includes('secure') && targetUrl.startsWith('https')) {
          findings.push({ title: 'Insecure Cookie', severity: 'YELLOW', what_it_is: 'A cookie is set without the Secure attribute.', why_dangerous: 'The cookie can be transmitted in cleartext over unencrypted HTTP connections.', fix_steps: ['Add the Secure flag to the cookie.'] });
        }
        if (!cookie.toLowerCase().includes('httponly')) {
          findings.push({ title: 'Missing HttpOnly Cookie', severity: 'YELLOW', what_it_is: 'A cookie is set without the HttpOnly attribute.', why_dangerous: 'The cookie can be accessed via client-side scripts, increasing XSS risk.', fix_steps: ['Add the HttpOnly flag to the cookie.'] });
        }
        if (!cookie.toLowerCase().includes('samesite')) {
          findings.push({ title: 'Missing SameSite Cookie Attribute', severity: 'BLUE', what_it_is: 'A cookie is set without the SameSite attribute.', why_dangerous: 'This increases the risk of Cross-Site Request Forgery (CSRF) attacks.', fix_steps: ['Add SameSite=Lax or Strict to the cookie.'] });
        }
      });
    }

    // CORS Check
    const acao = headers['access-control-allow-origin'];
    if (acao === '*') {
      findings.push({ title: 'Overly Permissive CORS', severity: 'YELLOW', what_it_is: 'Access-Control-Allow-Origin is set to *', why_dangerous: 'Any external domain can read responses from this server via client-side scripts if not properly restricted by authentication.', fix_steps: ['Set ACAO to specific trusted domains.'] });
    }

    return res.status(200).json({ success: true, findings, status: response.status });

  } catch (error) {
    return res.status(500).json({ error: `Header scan failed: ${error.message}` });
  }
};
