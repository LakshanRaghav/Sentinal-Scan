import axios from 'axios';
import fs from 'fs';
import path from 'path';

// Load env
const envPath = path.join(process.cwd(), '.env');
if (fs.existsSync(envPath)) {
  const envContent = fs.readFileSync(envPath, 'utf8');
  envContent.split('\n').forEach(line => {
    const [key, ...rest] = line.split('=');
    const value = rest.join('=');
    if (key && value) {
      process.env[key.trim()] = value.trim().replace(/^['"](.*)['"]$/, '$1');
    }
  });
}

const SYSTEM_PROMPT = `
You are SentinelScan's AI Security Analyst. Produce a structured, easy-to-understand executive report.
OUTPUT FORMAT — ALWAYS RESPOND IN EXACT JSON STRUCTURE ONLY. DO NOT WRAP THE RESPONSE IN MARKDOWN BACKTICKS (e.g. \`\`\`json). JUST RETURN THE RAW JSON OBJECT.
{
  "executive_summary": "test",
  "risk_score": 85,
  "risk_verdict": "test",
  "overall_severity": "RED",
  "priority_action": "test",
  "findings": []
}
`;

async function run() {
  console.log("Key starting with:", process.env.NVIDIA_API_KEY?.substring(0, 5));
  const startTime = Date.now();
  try {
    const response = await axios.post('https://integrate.api.nvidia.com/v1/chat/completions', {
      model: "meta/llama-3.1-70b-instruct",
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: `Analyze this: []` }
      ],
      temperature: 0.2,
      max_tokens: 3000
    }, {
      headers: {
        'Authorization': `Bearer ${process.env.NVIDIA_API_KEY}`,
        'Content-Type': 'application/json'
      },
      timeout: 30000 // 30s timeout
    });
    console.log("Time taken:", Date.now() - startTime, "ms");
    console.log(response.data.choices[0].message.content.substring(0, 100));
  } catch (e) {
    console.error("Failed:", e.message);
    if (e.response) console.error("Response data:", e.response.data);
  }
}
run();
