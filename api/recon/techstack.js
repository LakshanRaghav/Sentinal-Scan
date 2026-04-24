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

  const { targetUrl } = req.body;
  if (!targetUrl) return res.status(400).json({ error: 'targetUrl required' });

  const findings = [];
  const techStack = [];

  try {
    const response = await axios.get(targetUrl, { timeout: 5000, httpsAgent: agent, validateStatus: () => true });
    const headers = response.headers;
    const html = typeof response.data === 'string' ? response.data : '';

    // 1. Server & Tech Headers
    if (headers['server']) {
      techStack.push(`Server: ${headers['server']}`);
      findings.push({ title: 'Server Header Exposed', severity: 'BLUE', what_it_is: `Server is identifying as: ${headers['server']}`, why_dangerous: 'Helps attackers identify specific vulnerabilities for this server version.', evidence: headers['server'], fix_steps: ['Remove or spoof the Server header.'] });
    }
    if (headers['x-powered-by']) {
      techStack.push(`Powered-By: ${headers['x-powered-by']}`);
      findings.push({ title: 'X-Powered-By Header Exposed', severity: 'YELLOW', what_it_is: `Framework is identifying as: ${headers['x-powered-by']}`, why_dangerous: 'Leaking backend technology versions makes targeted attacks easier.', evidence: headers['x-powered-by'], fix_steps: ['Remove the X-Powered-By header.'] });
    }

    // 2. HTML Fingerprinting
    let wpVersion = null;
    if (html.includes('wp-content')) {
      techStack.push('WordPress');
      const match = html.match(/<meta name="generator" content="WordPress (.*?)"/i);
      if (match) wpVersion = match[1];
    }
    if (html.includes('_next/static')) techStack.push('Next.js');
    if (html.includes('data-reactroot') || html.includes('react_devtools')) techStack.push('React');
    if (html.includes('Laravel')) techStack.push('Laravel');

    // 3. WP Version Extraction & WPScan
    if (techStack.includes('WordPress')) {
      if (!wpVersion) {
        // Try grabbing readme.html
        try {
          const readmeRes = await axios.get(`${targetUrl}/readme.html`, { timeout: 3000, httpsAgent: agent });
          const rmMatch = readmeRes.data.match(/Version ([\d\.]+)/);
          if (rmMatch) wpVersion = rmMatch[1];
        } catch (e) {}
      }
      
      if (wpVersion) {
        techStack.push(`WordPress v${wpVersion}`);
        findings.push({ title: 'WordPress Version Exposed', severity: 'YELLOW', what_it_is: `WordPress version ${wpVersion} was detected.`, why_dangerous: 'Exposed versions allow attackers to quickly find known CVEs.', evidence: `WP v${wpVersion}`, fix_steps: ['Remove readme.html and generator meta tags.'] });
        
        // WPScan CVE Lookup
        if (process.env.WPSCAN_API_TOKEN) {
          try {
            const wpRes = await axios.get(`https://wpscan.com/api/v3/wordpresses/${wpVersion.replace(/\./g, '')}`, {
              headers: { 'Authorization': `Token ${process.env.WPSCAN_API_TOKEN}` },
              timeout: 4000
            });
            if (wpRes.data && wpRes.data[wpVersion] && wpRes.data[wpVersion].vulnerabilities) {
              const vulns = wpRes.data[wpVersion].vulnerabilities;
              vulns.forEach(v => {
                findings.push({ type: 'cms_cve', cve: v.cve ? \`CVE-\${v.cve}\` : null, title: `WP CVE: ${v.title}`, severity: 'CRITICAL', what_it_is: v.title, why_dangerous: 'Known WordPress vulnerability.', fix_steps: ['Update WordPress to the latest version immediately.'] });
              });
            }
          } catch(e) {}
        }
      }
    }

    // 4. Recon Files
    try {
      const robots = await axios.get(`${targetUrl}/robots.txt`, { timeout: 3000, httpsAgent: agent });
      if (robots.status === 200 && robots.data.includes('Disallow')) {
        findings.push({ title: 'robots.txt Found', severity: 'BLUE', what_it_is: 'The site exposes a robots.txt file.', why_dangerous: 'May accidentally reveal hidden or administrative paths to attackers.', evidence: `${targetUrl}/robots.txt`, fix_steps: ['Ensure no sensitive paths are exposed in robots.txt.'] });
      }
    } catch(e) {}

    // 5. WAF Detection
    try {
      const wafRes = await axios.get(`${targetUrl}?id=1 OR 1=1--`, { timeout: 3000, httpsAgent: agent, validateStatus: () => true });
      const wHeaders = wafRes.headers;
      let wafVendor = null;
      if (wHeaders['cf-ray']) wafVendor = 'Cloudflare';
      else if (wHeaders['x-sucuri-id']) wafVendor = 'Sucuri';
      else if (wHeaders['x-akamai-transformed']) wafVendor = 'Akamai';
      else if (wHeaders['x-powered-by-plesk']) wafVendor = 'Plesk';
      
      if (wafVendor) {
        techStack.push(`${wafVendor} WAF`);
        findings.push({ type: 'waf_detected', title: `WAF Detected (${wafVendor})`, severity: 'BLUE', what_it_is: `The site is protected by a ${wafVendor} Web Application Firewall.`, why_dangerous: 'Informational. The WAF might block or sanitize aggressive DAST payloads.', fix_steps: [] });
      }
    } catch(e) {}

    return res.status(200).json({ success: true, techStack: [...new Set(techStack)], findings });

  } catch (error) {
    return res.status(500).json({ error: `Tech Stack scan failed: ${error.message}` });
  }
};
