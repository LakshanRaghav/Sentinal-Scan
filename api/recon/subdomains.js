import axios from 'axios';
import dns from 'dns';
import https from 'https';
import { promisify } from 'util';

const resolveCname = promisify(dns.resolveCname);
const agent = new https.Agent({ rejectUnauthorized: false });

const TAKEOVER_TARGETS = {
  'github.io': 'There isn\\'t a GitHub Pages site here',
  'herokuapp.com': 'No such app',
  'azurewebsites.net': '404 Web Site not found',
  's3.amazonaws.com': 'The specified bucket does not exist',
  'fastly.net': 'Fastly error: unknown domain',
  'pantheonsite.io': 'The site you are looking for could not be found'
};

export default async (req, res) => {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { targetUrl } = req.body;
  if (!targetUrl) return res.status(400).json({ error: 'targetUrl required' });

  let domain;
  try {
    const parsed = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
    domain = parsed.hostname.replace('www.', '');
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  const findings = [];
  let subdomains = [];

  try {
    // 1. Fetch subdomains from crt.sh
    const response = await axios.get(`https://crt.sh/?q=%25.${domain}&output=json`, { timeout: 15000 });
    
    if (response.data && Array.isArray(response.data)) {
      const subs = response.data.map(entry => entry.name_value.toLowerCase());
      subdomains = [...new Set(subs)].filter(s => !s.includes('*')).slice(0, 30); // Cap at 30 to avoid timeout
      
      if (subdomains.length > 0) {
        findings.push({ title: 'Subdomains Discovered', severity: 'BLUE', what_it_is: `Found ${subdomains.length} subdomains via Certificate Transparency logs.`, why_dangerous: 'Exposed subdomains widen the attack surface.', evidence: subdomains.slice(0, 5).join(', ') + '...', fix_steps: ['Review all exposed subdomains to ensure they are intended to be public.'] });
      }

      // 2. Subdomain Takeover Detection
      await Promise.allSettled(subdomains.map(async (sub) => {
        try {
          const cnames = await resolveCname(sub);
          if (cnames && cnames.length > 0) {
            const cname = cnames[0].toLowerCase();
            
            // Check if CNAME points to a known vulnerable cloud provider
            const provider = Object.keys(TAKEOVER_TARGETS).find(p => cname.includes(p));
            if (provider) {
              // Fetch the site to check for the missing fingerprint
              try {
                const httpRes = await axios.get(`http://${sub}`, { timeout: 4000, validateStatus: () => true });
                const fingerprint = TAKEOVER_TARGETS[provider];
                
                if (typeof httpRes.data === 'string' && httpRes.data.includes(fingerprint)) {
                  findings.push({ 
                    type: 'subdomain_takeover', 
                    title: 'Subdomain Takeover Vulnerability', 
                    severity: 'CRITICAL', 
                    what_it_is: `The subdomain ${sub} has a dangling CNAME pointing to ${cname}.`, 
                    why_dangerous: `An attacker can claim this repository/bucket on ${provider} and serve malicious content under your domain.`, 
                    evidence: `CNAME: ${cname} | Status: ${httpRes.status}`, 
                    fix_steps: [`Remove the CNAME record for ${sub} from your DNS settings immediately.`, `Or claim the resource on ${provider}.`] 
                  });
                }
              } catch(e) {}
            }
          }
        } catch(e) {} // resolveCname throws if no CNAME exists, ignore
      }));
    }

    return res.status(200).json({ success: true, subdomains, findings });

  } catch (error) {
    return res.status(200).json({ success: false, findings: [{ title: 'Subdomain Recon Failed', severity: 'BLUE', what_it_is: 'Could not connect to crt.sh.', why_dangerous: 'Informational', fix_steps: [] }] });
  }
};
