import axios from 'axios';
import { load as loadCheerio } from 'cheerio';
import https from 'https';

// Disable SSL verification for testing (not recommended for production)
const agent = new https.Agent({
  rejectUnauthorized: false
});

const SYSTEM_PROMPT = `
You are SentinelScan's AI Security Analyst. Your job is to analyze real security scan results and produce a structured, easy-to-understand report for both technical and non-technical stakeholders.

CORE RULES:
1. Focus heavily on Information Leakage, Credential Exposure, Infrastructure misconfigurations, and Web Vulnerabilities detected in the RAW DATA.
2. Provide simple explanations without jargon, then a "why_dangerous", and "fix_steps".
3. Use the STRICT TRAFFIC LIGHT severity system ONLY:
   - RED: Immediate Danger (Fix within 1 hour). Use for truly dangerous exposed credentials, SQLi, XSS, open .env.
   - YELLOW: Potential Threat (Fix within 24 hours). Use for exposed infrastructure mapping or minor config leaks.
   - BLUE: Informational Recon. Use for missing headers or standard recon data. NOTE: Google API keys ("AIza...") in client code are usually public/restricted keys for YouTube/Maps. Classify them as BLUE (Informational) unless proven unrestricted.
4. If there are NO vulnerabilities, rate the site as BLUE. Do NOT hallucinate.
5. Incorporate empirical evidence (status_code, response_time, file_size). Provide a confidence_score (0-100%).
6. Do NOT assign RED severity without concrete verified snippets or if confidence_score < 75%.
7. If there are no real security issues, return an empty array \`[]\` for "findings". Do NOT generate placeholder or "None" findings.

OUTPUT FORMAT — Always respond in EXACT JSON structure:
{
  "executive_summary": "plain English, 3-4 sentences",
  "risk_score": 85,
  "risk_verdict": "Your site is leaking secrets. Fix immediately.",
  "overall_severity": "RED",
  "priority_action": "Single most important action",
  "findings": [
    {
      "title": "short title",
      "severity": "RED",
      "what_it_is": "explanation",
      "why_dangerous": "real-world consequence",
      "exposed_value_preview": "sk_l...K9p",
      "location": "https://example.com/api/config.js",
      "confidence_score": 98,
      "status_code": 200,
      "response_time": "124ms",
      "file_size": "2.4kb",
      "fix_steps": ["Step 1", "Step 2"],
      "fix_time": "15 minutes"
    }
  ]
}
`;

async function callNvidiaAPI(scanData) {
  const apiKey = process.env.NVIDIA_API_KEY;
  if (!apiKey) {
    throw new Error('NVIDIA_API_KEY not set');
  }

  const response = await axios.post('https://integrate.api.nvidia.com/v1/chat/completions', {
    model: "meta/llama-3.1-405b-instruct",
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: `Analyze this security scan data: ${JSON.stringify(scanData)}` }
    ],
    temperature: 0.2,
    max_tokens: 2048
  }, {
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    }
  });

  return response.data.choices[0].message.content;
}

function extractSecrets(text, url) {
  const findings = [];

  // AWS Keys
  const awsRegex = /AKIA[0-9A-Z]{16}/g;
  const awsMatches = text.match(awsRegex);
  if (awsMatches) {
    findings.push({
      type: 'aws_key',
      value: awsMatches[0],
      location: url
    });
  }

  // Stripe Keys
  const stripeRegex = /sk_(test|live)_[0-9a-zA-Z]{24}/g;
  const stripeMatches = text.match(stripeRegex);
  if (stripeMatches) {
    findings.push({
      type: 'stripe_key',
      value: stripeMatches[0],
      location: url
    });
  }

  // JWT Tokens
  const jwtRegex = /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.]+/g;
  const jwtMatches = text.match(jwtRegex);
  if (jwtMatches) {
    findings.push({
      type: 'jwt_token',
      value: jwtMatches[0].substring(0, 50) + '...',
      location: url
    });
  }

  return findings;
}

async function crawlWebsite(baseUrl) {
  const visited = new Set();
  const toVisit = [baseUrl];
  const findings = [];
  const startTime = Date.now();

  while (toVisit.length > 0 && visited.size < 20) { // Limit to 20 pages for Vercel stability
    const url = toVisit.shift();
    if (visited.has(url)) continue;
    visited.add(url);

    try {
      const response = await axios.get(url, {
        timeout: 10000,
        httpsAgent: agent,
        headers: {
          'User-Agent': 'SentinelScan/1.0'
        }
      });

      const $ = loadCheerio(response.data);
      const pageText = response.data;

      // Extract secrets
      const secrets = extractSecrets(pageText, url);
      findings.push(...secrets);

      // Find JS files
      $('script[src]').each((i, elem) => {
        const src = $(elem).attr('src');
        if (src && !src.startsWith('http') && !visited.has(src)) {
          const fullUrl = new URL(src, url).href;
          toVisit.push(fullUrl);
        }
      });

      // Find links
      $('a[href]').each((i, elem) => {
        const href = $(elem).attr('href');
        if (href && href.startsWith('/') && !href.includes('#')) {
          const fullUrl = new URL(href, url).href;
          if (!visited.has(fullUrl)) {
            toVisit.push(fullUrl);
          }
        }
      });

    } catch (error) {
      // Ignore errors for now
    }
  }

  return {
    findings,
    pagesScanned: visited.size,
    scanTime: Date.now() - startTime
  };
}

async function testVulnerabilities(url) {
  const vulnerabilities = [];

  // Simple SQLi test
  try {
    const sqliPayload = url + "?id=1' OR '1'='1";
    const response = await axios.get(sqliPayload, {
      timeout: 5000,
      httpsAgent: agent,
      validateStatus: () => true
    });

    if (response.data.toLowerCase().includes('sql') || response.data.toLowerCase().includes('syntax')) {
      vulnerabilities.push({
        type: 'sqli',
        location: sqliPayload,
        evidence: 'SQL error in response'
      });
    }
  } catch (error) {}

  // Simple XSS test
  try {
    const xssPayload = url + "?q=<script>alert(1)</script>";
    const response = await axios.get(xssPayload, {
      timeout: 5000,
      httpsAgent: agent,
      validateStatus: () => true
    });

    if (response.data.includes('<script>alert(1)</script>')) {
      vulnerabilities.push({
        type: 'xss',
        location: xssPayload,
        evidence: 'XSS payload reflected'
      });
    }
  } catch (error) {}

  return vulnerabilities;
}

export default async (req, res) => {
  // Set CORS headers
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

  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  try {
    // Send initial log
    res.write(JSON.stringify({ type: 'log', message: 'Initializing scan engine...', level: 'info' }) + '\n');

    // Crawl website
    res.write(JSON.stringify({ type: 'log', message: 'Deep web spider activated. Harvesting internal nodes...', level: 'info' }) + '\n');
    const crawlResult = await crawlWebsite(targetUrl);
    res.write(JSON.stringify({ type: 'log', message: `Crawled ${crawlResult.pagesScanned} pages in ${crawlResult.scanTime}ms`, level: 'info' }) + '\n');

    // Test vulnerabilities
    res.write(JSON.stringify({ type: 'log', message: 'Active DAST probes engaged. Testing for SQLi/XSS...', level: 'info' }) + '\n');
    const vulnResult = await testVulnerabilities(targetUrl);

    // Prepare data for AI analysis
    const scanData = {
      target: targetUrl,
      secrets: crawlResult.findings,
      vulnerabilities: vulnResult,
      pagesScanned: crawlResult.pagesScanned
    };

    res.write(JSON.stringify({ type: 'log', message: 'Neural analysis in progress...', level: 'info' }) + '\n');

    // Call NVIDIA API
    const aiResponse = await callNvidiaAPI(scanData);
    let report;
    try {
      report = JSON.parse(aiResponse);
    } catch (e) {
      // Fallback if AI doesn't return valid JSON
      report = {
        executive_summary: "AI analysis completed but returned invalid format.",
        risk_score: 50,
        risk_verdict: "Unable to determine risk level.",
        overall_severity: "BLUE",
        priority_action: "Review scan manually",
        findings: []
      };
    }

    // Send final report
    res.write(JSON.stringify({ type: 'report', data: report }) + '\n');

  } catch (error) {
    res.write(JSON.stringify({ type: 'log', message: `Scan failed: ${error.message}`, level: 'error' }) + '\n');
  }

  res.end();
};