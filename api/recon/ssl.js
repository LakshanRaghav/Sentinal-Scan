import tls from 'tls';
import { URL } from 'url';

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
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  const findings = [];
  let sslInfo = {};

  try {
    // 1. Standard TLS check (cert info, protocol, ocsp)
    await new Promise((resolve, reject) => {
      const socket = tls.connect(443, hostname, { servername: hostname, requestOCSP: true }, () => {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();

        sslInfo = {
          issuer: cert.issuer?.O || 'Unknown',
          subject: cert.subject?.CN || 'Unknown',
          valid_from: cert.valid_from,
          valid_to: cert.valid_to,
          protocol
        };

        const daysToExpiry = Math.floor((new Date(cert.valid_to) - new Date()) / (1000 * 60 * 60 * 24));
        if (daysToExpiry < 0) {
          findings.push({ title: 'SSL Certificate Expired', severity: 'RED', what_it_is: 'The SSL certificate has expired.', why_dangerous: 'Browsers will block users from visiting the site, and traffic is vulnerable to interception.', fix_steps: ['Renew and install a valid SSL certificate immediately.'] });
        } else if (daysToExpiry < 30) {
          findings.push({ title: 'SSL Certificate Expiring Soon', severity: 'YELLOW', what_it_is: `The certificate expires in ${daysToExpiry} days.`, why_dangerous: 'If not renewed, the site will become inaccessible.', fix_steps: ['Renew the certificate before it expires.'] });
        } else {
          findings.push({ title: 'Valid SSL Certificate', severity: 'BLUE', what_it_is: 'The certificate is valid.', why_dangerous: 'Informational', fix_steps: [] });
        }

        if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
          findings.push({ title: 'Obsolete TLS Protocol', severity: 'RED', what_it_is: `Server negotiated ${protocol}`, why_dangerous: 'Vulnerable to downgrade attacks like POODLE and BEAST.', fix_steps: ['Disable TLS 1.0 and 1.1 on the server.'] });
        } else {
          findings.push({ title: 'Modern TLS Supported', severity: 'BLUE', what_it_is: `Server negotiated ${protocol}`, why_dangerous: 'Informational', fix_steps: [] });
        }

        socket.end();
        resolve();
      });

      // OCSP Stapling check
      socket.on('OCSPResponse', (response) => {
        if (!response || response.length === 0) {
          findings.push({ type: 'ocsp_not_stapled', title: 'OCSP Stapling Not Enabled', severity: 'BLUE', what_it_is: 'The server does not staple OCSP responses.', why_dangerous: 'Clients must query the CA directly to verify revocation, slowing down connections and leaking privacy.', fix_steps: ['Enable OCSP stapling in the web server.'] });
        }
      });

      socket.on('error', reject);
    });

    // 2. Cipher Suite Enumeration (Weak Ciphers)
    const weakCiphers = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'ANON'];
    
    // Test each weak cipher class to see if the server accepts it
    for (const cipher of weakCiphers) {
      try {
        await new Promise((resolve, reject) => {
          const socket = tls.connect(443, hostname, { 
            servername: hostname, 
            ciphers: cipher, // Try to force weak cipher
            rejectUnauthorized: false
          }, () => {
            // If connection succeeds, it means it accepted the weak cipher
            const negotiated = socket.getCipher();
            findings.push({ 
              type: 'cipher_weak', 
              title: `Weak Cipher Suite Accepted (${cipher})`, 
              severity: 'YELLOW', 
              what_it_is: `Server accepted a ${cipher} cipher suite (${negotiated.name}).`, 
              why_dangerous: 'Weak ciphers are vulnerable to cryptographic attacks allowing traffic decryption.', 
              fix_steps: [`Disable ${cipher} cipher suites in web server configuration.`] 
            });
            socket.end();
            resolve();
          });
          socket.on('error', () => {
            // Error means connection refused/handshake failed (good!)
            resolve();
          });
        });
      } catch (e) {} // Ignore errors, means cipher rejected
    }

    return res.status(200).json({ success: true, sslInfo, findings });

  } catch (error) {
    return res.status(200).json({ success: false, sslInfo, findings: [{ title: 'SSL Audit Failed', severity: 'RED', what_it_is: 'Could not establish TLS connection.', why_dangerous: 'Server might be offline or not supporting HTTPS.', fix_steps: ['Ensure HTTPS is accessible.'] }] });
  }
};
