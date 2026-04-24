import dns from 'dns';
import { promisify } from 'util';
import { URL } from 'url';

const resolveTxt = promisify(dns.resolveTxt);
const resolveMx = promisify(dns.resolveMx);

export default async (req, res) => {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { targetUrl } = req.body;
  if (!targetUrl) return res.status(400).json({ error: 'targetUrl required' });

  let hostname;
  try {
    const parsed = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
    hostname = parsed.hostname;
    if (hostname.startsWith('www.')) hostname = hostname.replace('www.', '');
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  const findings = [];

  try {
    // 1. MX Records
    let mxRecords = [];
    try {
      mxRecords = await resolveMx(hostname);
      if (mxRecords.length === 0) {
        findings.push({ title: 'No MX Records Found', severity: 'BLUE', what_it_is: 'No mail servers configured.', why_dangerous: 'Domain cannot receive email.', fix_steps: [] });
      }
    } catch (e) {}

    // 2. SPF Check
    try {
      const txtRecords = await resolveTxt(hostname);
      let spfFound = false;
      txtRecords.forEach(record => {
        const txt = record.join('');
        if (txt.includes('v=spf1')) {
          spfFound = true;
          if (txt.includes('?all') || txt.includes('+all')) {
            findings.push({ title: 'Weak SPF Policy', severity: 'YELLOW', what_it_is: `SPF record is permissive: ${txt}`, why_dangerous: 'Allows unauthorized servers to send email on behalf of this domain, enabling phishing.', fix_steps: ['Change ?all or +all to -all or ~all.'] });
          } else {
            findings.push({ title: 'SPF Configured', severity: 'BLUE', what_it_is: `SPF record found: ${txt}`, why_dangerous: 'Informational', fix_steps: [] });
          }
        }
      });
      if (!spfFound) {
        findings.push({ title: 'Missing SPF Record', severity: 'YELLOW', what_it_is: 'No SPF record found.', why_dangerous: 'Attackers can spoof emails from this domain.', fix_steps: ['Create an SPF TXT record for the domain.'] });
      }
    } catch (e) {}

    // 3. DMARC Check
    try {
      const dmarcRecords = await resolveTxt(`_dmarc.${hostname}`);
      let dmarcFound = false;
      dmarcRecords.forEach(record => {
        const txt = record.join('');
        if (txt.includes('v=DMARC1')) {
          dmarcFound = true;
          if (txt.includes('p=none')) {
            findings.push({ title: 'DMARC in Monitoring Mode', severity: 'YELLOW', what_it_is: `DMARC policy is p=none: ${txt}`, why_dangerous: 'Spoofed emails are not blocked by receiving servers.', fix_steps: ['Change DMARC policy to p=quarantine or p=reject.'] });
          }
          
          if (!txt.includes('rua=')) {
            findings.push({ type: 'dmarc_no_reporting', title: 'DMARC No Reporting', severity: 'YELLOW', what_it_is: 'rua tag missing in DMARC record', why_dangerous: 'DMARC failures are silent. You have no visibility into spoofing attempts.', fix_steps: ['Add a rua=mailto:address to the DMARC record.'] });
          }
          
          if (txt.includes('adkim=r') || txt.includes('aspf=r')) {
            findings.push({ type: 'dmarc_relaxed_alignment', title: 'DMARC Relaxed Alignment', severity: 'BLUE', what_it_is: 'DKIM/SPF alignment is relaxed (adkim=r or aspf=r)', why_dangerous: 'Informational finding.', fix_steps: [] });
          }
        }
      });
      if (!dmarcFound) {
        findings.push({ title: 'Missing DMARC Record', severity: 'YELLOW', what_it_is: 'No DMARC record found.', why_dangerous: 'Receiving servers do not know how to handle spoofed emails.', fix_steps: ['Create a _dmarc TXT record.'] });
      }
    } catch (e) {
      findings.push({ title: 'Missing DMARC Record', severity: 'YELLOW', what_it_is: 'No _dmarc subdomain found.', why_dangerous: 'Receiving servers do not know how to handle spoofed emails.', fix_steps: ['Create a _dmarc TXT record.'] });
    }

    // 4. DKIM Check
    const selectors = ['default', 'google', 'mail', 's1', 's2', 'k1', 'selector1', 'selector2'];
    let dkimFound = false;
    for (const selector of selectors) {
      try {
        const dkimRecords = await resolveTxt(`${selector}._domainkey.${hostname}`);
        if (dkimRecords.length > 0) dkimFound = true;
      } catch(e) {}
    }
    
    if (!dkimFound) {
      findings.push({ type: 'dkim_missing', title: 'Missing DKIM Records', severity: 'YELLOW', what_it_is: 'Could not find DKIM records using common selectors.', why_dangerous: 'Emails may lack cryptographic signatures, increasing the chance of being marked as spam or spoofed.', fix_steps: ['Configure DKIM for your email sender.'] });
    }

    return res.status(200).json({ success: true, findings });

  } catch (error) {
    return res.status(500).json({ error: `DNS scan failed: ${error.message}` });
  }
};
