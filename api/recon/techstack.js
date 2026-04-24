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
    const techStack = [];
    
    // Check main page
    const mainResponse = await axios.get(targetUrl, { timeout: 5000, httpsAgent: agent, validateStatus: () => true });
    const headers = mainResponse.headers;
    const html = mainResponse.data;

    // Server Header
    if (headers['server']) {
      techStack.push(`Server: ${headers['server']}`);
      findings.push({ title: 'Server Header Exposed', severity: 'BLUE', what_it_is: `Server is identifying as: ${headers['server']}`, why_dangerous: 'Helps attackers identify specific vulnerabilities for this server version.', fix_steps: ['Obscure or remove the Server header.'] });
    }

    // X-Powered-By Header
    if (headers['x-powered-by']) {
      techStack.push(`Powered-By: ${headers['x-powered-by']}`);
      findings.push({ title: 'X-Powered-By Header Exposed', severity: 'BLUE', what_it_is: `Backend framework is: ${headers['x-powered-by']}`, why_dangerous: 'Reveals backend technology stack to attackers.', fix_steps: ['Remove the X-Powered-By header.'] });
    }

    // Fingerprint CMS/Framework from HTML
    if (typeof html === 'string') {
      if (html.includes('wp-content')) { techStack.push('WordPress'); }
      if (html.includes('id="__next"')) { techStack.push('Next.js'); }
      if (html.includes('data-reactroot')) { techStack.push('React'); }
      if (html.includes('generator" content="Drupal')) { techStack.push('Drupal'); }
      if (html.includes('laravel')) { techStack.push('Laravel'); }
    }

    // Check robots.txt
    try {
      const robotsUrl = new URL('/robots.txt', targetUrl).href;
      const robotsResp = await axios.get(robotsUrl, { timeout: 3000, httpsAgent: agent, validateStatus: () => true });
      if (robotsResp.status === 200 && typeof robotsResp.data === 'string' && robotsResp.data.includes('User-agent')) {
        findings.push({ title: 'robots.txt Found', severity: 'BLUE', what_it_is: 'The site exposes a robots.txt file.', why_dangerous: 'May accidentally reveal hidden or administrative paths to attackers.', location: robotsUrl });
      }
    } catch(e) {}

    // Check sitemap.xml
    try {
      const sitemapUrl = new URL('/sitemap.xml', targetUrl).href;
      const sitemapResp = await axios.get(sitemapUrl, { timeout: 3000, httpsAgent: agent, validateStatus: () => true });
      if (sitemapResp.status === 200 && typeof sitemapResp.data === 'string' && sitemapResp.data.includes('<urlset')) {
        findings.push({ title: 'sitemap.xml Found', severity: 'BLUE', what_it_is: 'The site exposes a sitemap.xml file.', why_dangerous: 'Allows attackers to easily map the entire attack surface.', location: sitemapUrl });
      }
    } catch(e) {}

    return res.status(200).json({ success: true, findings, techStack: [...new Set(techStack)] });

  } catch (error) {
    return res.status(500).json({ error: `TechStack scan failed: ${error.message}` });
  }
};
