import axios from 'axios';
import https from 'https';

const agent = new https.Agent({ rejectUnauthorized: false });

export default async (req, res) => {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  let { targetUrl } = req.body;
  if (!targetUrl) return res.status(400).json({ error: 'targetUrl required' });
  if (!targetUrl.startsWith('http')) targetUrl = `https://${targetUrl}`;

  try {
    const findings = [];
    
    // Quick SQLi Test (Time-based or Error-based reflection)
    try {
      const sqliUrl = new URL(targetUrl);
      sqliUrl.searchParams.append('id', "1' OR '1'='1");
      const sqliResp = await axios.get(sqliUrl.href, { timeout: 3000, httpsAgent: agent, validateStatus: () => true });
      const html = typeof sqliResp.data === 'string' ? sqliResp.data.toLowerCase() : '';
      if (html.includes('sql syntax') || html.includes('mysql_fetch') || html.includes('ora-')) {
        findings.push({ title: 'SQL Injection Possible', severity: 'RED', what_it_is: 'Database error detected in response to SQL payload.', why_dangerous: 'Attackers could read, modify, or delete database information.', location: sqliUrl.href, fix_steps: ['Use prepared statements or parameterized queries.'] });
      }
    } catch(e) {}

    // Quick XSS Test
    try {
      const xssUrl = new URL(targetUrl);
      xssUrl.searchParams.append('q', '<script>alert("sentinel")</script>');
      const xssResp = await axios.get(xssUrl.href, { timeout: 3000, httpsAgent: agent, validateStatus: () => true });
      if (typeof xssResp.data === 'string' && xssResp.data.includes('<script>alert("sentinel")</script>')) {
        findings.push({ title: 'Reflected XSS Possible', severity: 'RED', what_it_is: 'Script payload reflected unescaped in response.', why_dangerous: 'Attackers can execute malicious scripts in victims browsers.', location: xssUrl.href, fix_steps: ['Properly encode and sanitize all user input before reflecting it in HTML.'] });
      }
    } catch(e) {}

    // LFI / Sensitive File Test
    try {
      const lfiUrl = new URL(targetUrl);
      lfiUrl.pathname = '/.env';
      const lfiResp = await axios.get(lfiUrl.href, { timeout: 3000, httpsAgent: agent, validateStatus: () => true });
      if (lfiResp.status === 200 && typeof lfiResp.data === 'string' && lfiResp.data.includes('APP_KEY=')) {
         findings.push({ title: 'Exposed .env File', severity: 'RED', what_it_is: 'The application environment file is publicly accessible.', why_dangerous: 'Exposes extreme sensitive credentials and API keys.', location: lfiUrl.href, fix_steps: ['Block access to hidden files/directories in your web server config.'] });
      }
    } catch(e) {}

    return res.status(200).json({ success: true, findings });

  } catch (error) {
    return res.status(500).json({ error: `DAST scan failed: ${error.message}` });
  }
};
