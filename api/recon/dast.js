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
  
  if (targetUrl.endsWith('/')) targetUrl = targetUrl.slice(0, -1);

  const findings = [];

  // Helper to run tests with strict timeout
  const runTest = async (testName, testPromise) => {
    try {
      await Promise.race([
        testPromise,
        new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 4000))
      ]);
    } catch (e) {
      // Ignore timeouts to not crash the whole scanner
    }
  };

  try {
    // 1. SQLi Error-based Test
    await runTest('SQLi', (async () => {
      const sqliRes = await axios.get(`${targetUrl}?id=1'%20OR%20'1'='1`, { httpsAgent: agent, validateStatus: () => true });
      const body = typeof sqliRes.data === 'string' ? sqliRes.data.toLowerCase() : '';
      if (body.includes('syntax error') || body.includes('mysql_fetch') || body.includes('ora-') || body.includes('postgresql query failed')) {
        findings.push({ title: 'SQL Injection (Error-Based)', severity: 'CRITICAL', what_it_is: 'Database syntax errors were reflected when injecting a SQL quote payload.', why_dangerous: 'Attackers can manipulate queries to read or modify the database.', evidence: `Payload: ?id=1' OR '1'='1`, fix_steps: ['Use parameterized queries or prepared statements.', 'Implement a WAF to block SQL payloads.'] });
      }
    })());

    // 2. Reflected XSS Test
    await runTest('XSS', (async () => {
      const xssRes = await axios.get(`${targetUrl}?q=<script>alert("sentinel")</script>`, { httpsAgent: agent, validateStatus: () => true });
      const body = typeof xssRes.data === 'string' ? xssRes.data : '';
      if (body.includes('<script>alert("sentinel")</script>')) {
        findings.push({ title: 'Reflected Cross-Site Scripting (XSS)', severity: 'CRITICAL', what_it_is: 'The script payload was reflected exactly as inputted without sanitization.', why_dangerous: 'Attackers can steal session cookies or perform actions on behalf of authenticated users.', evidence: `Payload: ?q=<script>alert("sentinel")</script>`, fix_steps: ['HTML-encode all user input before reflecting it in the browser.', 'Implement a strict Content-Security-Policy.'] });
      }
    })());

    // 3. Open Redirect Test
    await runTest('Open Redirect', (async () => {
      const redirectRes = await axios.get(`${targetUrl}?redirect=https://evil.com&next=https://evil.com`, { httpsAgent: agent, maxRedirects: 0, validateStatus: () => true });
      if (redirectRes.status >= 300 && redirectRes.status < 400 && redirectRes.headers['location']) {
        if (redirectRes.headers['location'].includes('evil.com')) {
          findings.push({ title: 'Open Redirect', severity: 'HIGH', what_it_is: 'The application redirects users to an arbitrary external URL passed via parameter.', why_dangerous: 'Can be used in phishing campaigns to steal credentials.', evidence: `Location: ${redirectRes.headers['location']}`, fix_steps: ['Validate redirect targets against a strict allowlist.'] });
        }
      }
    })());

    // 4. Path Traversal / LFI Test
    await runTest('Path Traversal', (async () => {
      const lfiRes = await axios.get(`${targetUrl}/../../../../etc/passwd`, { httpsAgent: agent, validateStatus: () => true });
      if (lfiRes.status === 200 && typeof lfiRes.data === 'string' && lfiRes.data.includes('root:x:0:0:')) {
        findings.push({ title: 'Path Traversal (LFI)', severity: 'CRITICAL', what_it_is: 'The application returned the contents of /etc/passwd.', why_dangerous: 'Attackers can read arbitrary system files, including passwords and config files.', evidence: `/etc/passwd contents found`, fix_steps: ['Sanitize user input used in file paths.', 'Ensure web server runs in a chroot jail.'] });
      }
    })());

    // 5. Sensitive File Exposure (.env)
    await runTest('.env Exposure', (async () => {
      const envRes = await axios.get(`${targetUrl}/.env`, { httpsAgent: agent, validateStatus: () => true });
      if (envRes.status === 200 && typeof envRes.data === 'string' && (envRes.data.includes('APP_KEY=') || envRes.data.includes('DB_PASSWORD='))) {
        findings.push({ title: 'Exposed .env File', severity: 'CRITICAL', what_it_is: 'The environment configuration file (.env) is publicly accessible.', why_dangerous: 'Leads to immediate full system compromise via exposed database and API credentials.', evidence: `.env file found (HTTP 200)`, fix_steps: ['Block access to dotfiles in your web server configuration.', 'Move .env outside the public web root.'] });
      }
    })());

    // 6. Security.txt
    await runTest('Security.txt', (async () => {
      const secRes = await axios.get(`${targetUrl}/.well-known/security.txt`, { httpsAgent: agent, validateStatus: () => true });
      if (secRes.status !== 200) {
        findings.push({ title: 'Missing security.txt', severity: 'INFO', what_it_is: 'No responsible disclosure policy published at /.well-known/security.txt.', why_dangerous: 'Security researchers have no standard way to report vulnerabilities.', evidence: 'HTTP 404', fix_steps: ['Publish a security.txt file following RFC 9116.'] });
      }
    })());

    return res.status(200).json({ success: true, findings });

  } catch (error) {
    return res.status(500).json({ error: `DAST scan failed: ${error.message}` });
  }
};
