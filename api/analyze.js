import axios from 'axios';

const SYSTEM_PROMPT = `
You are SentinelScan's AI Security Analyst. Your job is to analyze the raw JSON reconnaissance data provided (Headers, DNS, SSL, Subdomains, Tech Stack, DAST) and produce a structured, industry-standard penetration testing report.

CORE RULES:
1. Synthesize the findings. Group related vulnerabilities into coherent narratives.
2. Provide simple, impact-focused explanations.
3. Derive CVSS 3.1 base scores (0.0 to 10.0) from the raw data severity.
4. Map each finding to the closest CWE ID and OWASP Top 10 category.
5. Trust the provided JSON data. Do not invent vulnerabilities.
6. Missing headers or missing cookies are NOT critical vulnerabilities; they are "informational" or "low".

OUTPUT FORMAT — ALWAYS RESPOND IN EXACT JSON STRUCTURE ONLY. NO MARKDOWN. NO PREAMBLE.
{
  "executive_summary": "Plain English, 3-4 sentences summarizing the security posture.",
  "risk_score": 85,
  "risk_verdict": "CRITICAL RISK",
  "overall_severity": "critical",
  "priority_action": "Fix SQL injection on /login",
  "severity_breakdown": { "critical": 1, "high": 0, "medium": 1, "low": 2, "informational": 5 },
  "compliance_impact": { 
    "pci_dss": "Non-compliant due to weak TLS", 
    "gdpr": "Potential non-compliance due to PII exposure risk", 
    "iso_27001": "Fails A.14.2.5 due to missing secure engineering principles" 
  },
  "findings": [
    {
      "id": "VULN-001",
      "title": "Short title",
      "severity": "critical",
      "cvss_score": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cwe_id": "CWE-89",
      "cve": null,
      "owasp_category": "A03:2021-Injection",
      "module": "DAST",
      "affected_component": "example.com",
      "impact": "Explanation of real-world consequence",
      "remediation": ["Step 1", "Step 2"],
      "evidence": { "Payload": "?id=1' OR 1=1--" },
      "compliance_tags": ["PCI-DSS", "ISO-27001"]
    }
  ]
}
`;

async function callNvidiaAPI(scanData) {
  const apiKey = process.env.NVIDIA_API_KEY;
  if (!apiKey) throw new Error('NVIDIA_API_KEY not set');

  const response = await axios.post('https://integrate.api.nvidia.com/v1/chat/completions', {
    model: "meta/llama-3.1-70b-instruct",
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: `Analyze this aggregated security scan data: ${JSON.stringify(scanData)}` }
    ],
    temperature: 0.2,
    max_tokens: 4000
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
        overall_severity: "info",
        priority_action: "Review scan manually",
        severity_breakdown: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
        compliance_impact: { pci_dss: "Unknown", gdpr: "Unknown", iso_27001: "Unknown" },
        findings: []
      };
    }

    return res.status(200).json({ success: true, report });

  } catch (error) {
    return res.status(500).json({ error: `AI Analysis failed: ${error.message}` });
  }
};