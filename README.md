# 🛡️ SentinelScan - Autonomous AI Security Analyst

SentinelScan is a powerful, autonomous security scanner that combines deep web spidering, dynamic application security testing (DAST), and AI-driven analysis to identify vulnerabilities in real-time.

## 🚀 Features

- **Deep Web Spider:** Automatically crawls internal nodes and harvests JavaScript assets.
- **Regex Matching Engine:** Detects leaked AWS keys, Stripe secrets, JWT tokens, and more.
- **Active DAST Probes:** Tests for SQL Injection (SQLi) and Cross-Site Scripting (XSS) on discovered endpoints.
- **AI Analysis:** Utilizes NVIDIA's Neural Engine (Llama 3.1) to generate structured, human-readable security reports.
- **Real-time Telemetry:** Streams scan progress and findings via a modern, dark-themed dashboard.

## 🛠️ Setup & Installation

### Prerequisites

- **Node.js 18+**
- **NVIDIA API Key** (for AI analysis)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/sentinel-scan-vercel.git
   cd sentinel-scan-vercel
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Set up environment variables:
   - Copy `.env.example` to `.env`
   - Add your `NVIDIA_API_KEY` to the `.env` file

4. For local development:
   ```bash
   npm run dev
   ```

## 🚀 Deployment to Vercel

1. **Connect to Vercel:**
   - Import your GitHub repository to Vercel
   - Vercel will automatically detect the configuration

2. **Environment Variables:**
   - In Vercel dashboard, add `NVIDIA_API_KEY` as an environment variable

3. **Deploy:**
   - Push to main branch or deploy manually
   - Your app will be live at `https://your-project.vercel.app`

## 📂 Project Structure

- `index.html`: The modern security dashboard UI.
- `app.js`: Frontend logic for real-time telemetry streaming.
- `style.css`: Dark-themed styling.
- `config.js`: Configuration file.
- `api/analyze.js`: Serverless function for scanning and AI analysis.
- `package.json`: Node.js dependencies and scripts.
- `vercel.json`: Vercel deployment configuration.

## ⚠️ Disclaimer

This tool is intended for **educational and security testing purposes only**. Unauthorized scanning of websites you do not own or have explicit permission to test is illegal and unethical.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details.

---
Built with ❤️ using Vercel and NVIDIA AI