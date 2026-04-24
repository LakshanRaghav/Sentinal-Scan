import axios from 'axios';

const SYSTEM_PROMPT = `
You are SentinelScan's AI Security Analyst. Your job is to analyze the raw JSON reconnaissance data provided (Headers, DNS, SSL, Subdomains, Tech Stack, DAST) and produce a structured, easy-to-understand executive report.

CORE RULES:
1. Synthesize the findings. If multiple checks flag the same issue (e.g. missing Secure cookie and missing HSTS), group them into a coherent narrative.
2. Provide simple explanations without jargon, then a "why_dangerous", and "fix_steps".
3. Use the STRICT TRAFFIC LIGHT severity system ONLY:
   - RED: Immediate Danger (Fix within 1 hour). Example: SQLi, XSS, Expired SSL, Open .env.
   - YELLOW: Potential Threat (Fix within 24 hours). Example: Missing DMARC, Overly Permissive CORS.
   - BLUE: Informational Recon or Hygiene. Example: Missing Security Headers (CSP, HSTS), Insecure Cookies, Server Headers, found subdomains, valid SSL.
4. If there are NO major vulnerabilities (RED) or significant threats (YELLOW), rate the overall severity as BLUE. Do NOT hallucinate. Do NOT call missing headers or cookies "critical vulnerabilities" - they are just hygiene findings.
5. Trust the provided JSON data. Do not invent vulnerabilities that aren't in the input.

OUTPUT FORMAT — ALWAYS RESPOND IN EXACT JSON STRUCTURE ONLY. DO NOT WRAP THE RESPONSE IN MARKDOWN BACKTICKS (e.g. \`\`\`json). JUST RETURN THE RAW JSON OBJECT.
{
  "executive_summary": "plain English, 3-4 sentences summarizing the security posture.",
  "risk_score": 85,
  "risk_verdict": "Your site has critical vulnerabilities. Fix immediately.",
  "overall_severity": "RED",
  "priority_action": "Single most important action (e.g., Fix SQL injection on /login)",
  "findings": [
    {
      "title": "short title",
      "severity": "RED",
      "what_it_is": "explanation",
      "why_dangerous": "real-world consequence",
      "exposed_value_preview": "Snippet or evidence if applicable",
      "location": "URL or Component",
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
    model: "meta/llama-3.1-70b-instruct",
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: `Analyze this aggregated security scan data: ${JSON.stringify(scanData)}` }
    ],
    temperature: 0.2,
    max_tokens: 3000
  }, {
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    }
  });

  return response.data.choices[0].message.content;
}

export default async (req, res) => {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { targetUrl, aggregatedData } = req.body;
  if (!targetUrl || !aggregatedData) {
    return res.status(400).json({ error: 'targetUrl and aggregatedData required' });
  }

  try {
    const aiResponse = await callNvidiaAPI({ target: targetUrl, data: aggregatedData });
    let report;
    try {
      // Strip markdown JSON wrapping if the AI ignored instructions
      let cleanResponse = aiResponse.trim();
      if (cleanResponse.startsWith('```json')) cleanResponse = cleanResponse.substring(7);
      if (cleanResponse.startsWith('```')) cleanResponse = cleanResponse.substring(3);
      if (cleanResponse.endsWith('```')) cleanResponse = cleanResponse.substring(0, cleanResponse.length - 3);
      
      report = JSON.parse(cleanResponse.trim());
    } catch (e) {
      console.error('JSON Parse Error:', e, 'Raw AI Response:', aiResponse);
      report = {
        executive_summary: "AI analysis completed but returned invalid format. See logs.",
        risk_score: 50,
        risk_verdict: "Unable to determine risk level.",
        overall_severity: "BLUE",
        priority_action: "Review scan manually",
        findings: []
      };
    }

    return res.status(200).json({ success: true, report });

  } catch (error) {
    return res.status(500).json({ error: `AI Analysis failed: ${error.message}` });
  }
};