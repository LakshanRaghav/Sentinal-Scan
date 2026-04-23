import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import analyze from './api/analyze.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3000;

const server = http.createServer(async (req, res) => {
  console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${req.url}`);

  // API endpoint
  if (req.url === '/api/analyze' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    req.on('end', async () => {
      try {
        req.body = JSON.parse(body);
        console.log('Route matched: /api/analyze');
        await analyze(req, res);
      } catch (e) {
        console.error('Error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // Static files
  let filePath = req.url === '/' ? '/index.html' : req.url;
  filePath = path.join(__dirname, filePath);

  try {
    if (fs.existsSync(filePath)) {
      const ext = path.extname(filePath);
      const mimeTypes = {
        '.html': 'text/html',
        '.css': 'text/css',
        '.js': 'application/javascript',
        '.json': 'application/json'
      };
      const contentType = mimeTypes[ext] || 'text/plain';

      const file = fs.readFileSync(filePath);
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(file);
    } else {
      res.writeHead(404);
      res.end('Not found');
    }
  } catch (e) {
    res.writeHead(500);
    res.end('Server error');
  }
});

server.listen(PORT, () => {
  console.log(`\n✅ Local dev server running at http://localhost:${PORT}`);
  console.log(`\n⚠️  Set NVIDIA_API_KEY environment variable for scanning:`);
  console.log(`   $env:NVIDIA_API_KEY="your-key-here"\n`);
});
