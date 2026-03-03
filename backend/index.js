import express from 'express';
import cors from 'cors';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { parsePcap } from './pcapAnalyzer.js';
import { generatePDFReport } from './pdfGenerator.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = 3001;

app.use(cors());
app.use(express.json());

const upload = multer({ dest: path.join(__dirname, 'uploads/') });

// Ensure uploads dir exists
if (!fs.existsSync(path.join(__dirname, 'uploads'))) {
  fs.mkdirSync(path.join(__dirname, 'uploads'));
}

app.post('/api/analyze', upload.single('pcap'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No PCAP file uploaded' });
    }

    const { blockedApps = '[]', blockedIPs = '[]', blockedDomains = '[]' } = req.body;
    
    // Parse the PCAP
    const analysisResult = await parsePcap(
      req.file.path,
      JSON.parse(blockedApps),
      JSON.parse(blockedIPs),
      JSON.parse(blockedDomains)
    );

    // Clean up uploaded file
    fs.unlinkSync(req.file.path);

    res.json(analysisResult);
  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({ error: 'Failed to analyze PCAP file: ' + error.message });
  }
});

app.post('/api/report/pdf', async (req, res) => {
  try {
    const analysisData = req.body;
    if (!analysisData || !analysisData.stats) {
      return res.status(400).json({ error: 'Invalid analysis data' });
    }

    const pdfBytes = await generatePDFReport(analysisData);
    
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename=DPI_Engine_Report.pdf');
    res.send(Buffer.from(pdfBytes));
  } catch (error) {
    console.error('PDF generation error:', error);
    res.status(500).json({ error: 'Failed to generate PDF report: ' + error.message });
  }
});

app.listen(port, () => {
  console.log(`DPI Engine Backend API running on http://localhost:${port}`);
});
