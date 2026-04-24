import dns from 'dns/promises';

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
    let hostname = urlObj.hostname;
    
    // For DMARC, we usually want the root domain. Let's try root domain if www is present.
    const rootDomain = hostname.startsWith('www.') ? hostname.substring(4) : hostname;

    const findings = [];
    const records = { txt: [], mx: [], dmarc: [] };

    // TXT & SPF
    try {
      const txtRecords = await dns.resolveTxt(hostname);
      records.txt = txtRecords.map(r => r.join(''));
      
      const spf = records.txt.find(r => r.startsWith('v=spf1'));
      if (spf) {
        if (spf.includes('~all') || spf.includes('-all')) {
          findings.push({ title: 'SPF Record Found', severity: 'BLUE', what_it_is: 'Sender Policy Framework (SPF) is configured.', why_dangerous: 'Helps prevent email spoofing.' });
        } else if (spf.includes('?all') || spf.includes('+all')) {
          findings.push({ title: 'Weak SPF Record', severity: 'YELLOW', what_it_is: 'SPF is configured but is overly permissive.', why_dangerous: 'Does not effectively prevent email spoofing.', fix_steps: ['Update SPF record to end with ~all or -all.'] });
        }
      } else {
        findings.push({ title: 'Missing SPF Record', severity: 'YELLOW', what_it_is: 'No SPF record found.', why_dangerous: 'Domain is highly susceptible to email spoofing and phishing attacks.', fix_steps: ['Publish an SPF TXT record for the domain.'] });
      }
    } catch (e) {
      if (e.code !== 'ENODATA' && e.code !== 'ENOTFOUND') console.error('TXT lookup failed:', e.message);
    }

    // DMARC
    try {
      const dmarcRecords = await dns.resolveTxt(`_dmarc.${rootDomain}`);
      records.dmarc = dmarcRecords.map(r => r.join(''));
      const dmarc = records.dmarc.find(r => r.startsWith('v=DMARC1'));
      
      if (dmarc) {
        if (dmarc.includes('p=none')) {
          findings.push({ title: 'DMARC Policy is None', severity: 'YELLOW', what_it_is: 'DMARC is configured but in monitoring mode only.', why_dangerous: 'Spoofed emails will still be delivered.', fix_steps: ['Gradually move DMARC policy to p=quarantine or p=reject.'] });
        } else {
          findings.push({ title: 'DMARC Configured Properly', severity: 'BLUE', what_it_is: 'DMARC is actively protecting the domain.', why_dangerous: 'Informational.' });
        }
      } else {
         findings.push({ title: 'Missing DMARC Record', severity: 'YELLOW', what_it_is: 'No DMARC record found.', why_dangerous: 'Domain is susceptible to spoofing without enforcement.', fix_steps: ['Publish a DMARC record at _dmarc.' + rootDomain] });
      }
    } catch (e) {
      findings.push({ title: 'Missing DMARC Record', severity: 'YELLOW', what_it_is: 'No DMARC record found.', why_dangerous: 'Domain is susceptible to spoofing without enforcement.', fix_steps: ['Publish a DMARC record at _dmarc.' + rootDomain] });
    }

    // MX
    try {
      records.mx = await dns.resolveMx(hostname);
    } catch (e) {
      if (e.code !== 'ENODATA' && e.code !== 'ENOTFOUND') console.error('MX lookup failed:', e.message);
    }

    return res.status(200).json({ success: true, findings, records });

  } catch (error) {
    return res.status(500).json({ error: `DNS scan failed: ${error.message}` });
  }
};
