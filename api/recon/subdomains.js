import axios from 'axios';

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
    let hostname;
    try {
      hostname = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`).hostname;
    } catch(e) {
      hostname = targetUrl;
    }

    // Strip www. to get root domain for broader subdomain search
    const rootDomain = hostname.startsWith('www.') ? hostname.substring(4) : hostname;

    const response = await axios.get(`https://crt.sh/?q=${rootDomain}&output=json`, {
      timeout: 8000 // 8 second timeout, crt.sh can be slow
    });

    const findings = [];
    let subdomains = [];

    if (response.data && Array.isArray(response.data)) {
      const allNames = response.data.map(entry => entry.name_value);
      
      // Clean and unique the names
      const uniqueNames = new Set();
      allNames.forEach(name => {
        name.split('\\n').forEach(sub => {
          let cleanSub = sub.replace('*.', '').trim();
          if (cleanSub !== rootDomain && cleanSub.endsWith(rootDomain)) {
            uniqueNames.add(cleanSub);
          }
        });
      });

      subdomains = Array.from(uniqueNames).slice(0, 20); // Limit to 20 to avoid overwhelming report

      if (subdomains.length > 0) {
        findings.push({ 
          title: 'Exposed Subdomains Found', 
          severity: 'BLUE', 
          what_it_is: `Discovered ${uniqueNames.size} subdomains via Certificate Transparency logs.`, 
          why_dangerous: 'Forgotten or exposed subdomains often host vulnerable development or admin panels.',
          exposed_value_preview: subdomains.slice(0, 3).join(', ') + '...'
        });
      }
    }

    return res.status(200).json({ success: true, findings, subdomains });

  } catch (error) {
    // Return graceful failure since crt.sh is often flaky
    return res.status(200).json({ 
      success: true, 
      findings: [{ title: 'Subdomain Enum Failed', severity: 'BLUE', what_it_is: 'crt.sh timed out.', why_dangerous: 'N/A' }],
      subdomains: [] 
    });
  }
};
