import { PDFDocument, rgb, StandardFonts } from 'pdf-lib';

export async function generatePDFReport(data) {
  const { stats, appBreakdown, protocolBreakdown } = data;
  
  const pdfDoc = await PDFDocument.create();
  let page = pdfDoc.addPage([595.28, 841.89]); // A4 size
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const boldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  
  let y = 800;
  
  // Title
  page.drawText('DPI ENGINE - ANALYSIS REPORT', { x: 50, y, size: 24, font: boldFont, color: rgb(0, 0.5, 0.8) });
  y -= 40;
  
  page.drawText(`Generated on: ${new Date().toLocaleString()}`, { x: 50, y, size: 12, font });
  y -= 40;

  // Overview Stats
  page.drawText('OVERVIEW', { x: 50, y, size: 16, font: boldFont });
  y -= 25;
  
  const formatNum = (n) => n.toLocaleString();
  const formatBytes = (bytes) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
  };

  const drawKV = (k, v) => {
    page.drawText(`${k}:`, { x: 50, y, size: 12, font: boldFont });
    page.drawText(v.toString(), { x: 200, y, size: 12, font });
    y -= 20;
  };

  drawKV('Total Packets', formatNum(stats.totalPackets));
  drawKV('Total Bytes', formatBytes(stats.totalBytes));
  drawKV('Forwarded Packets', formatNum(stats.forwarded));
  drawKV('Dropped Packets', formatNum(stats.dropped));
  drawKV('Active Flows', formatNum(stats.activeFlows));
  y -= 20;

  // Protocol Stats
  page.drawText('PROTOCOL DISTRIBUTION', { x: 50, y, size: 16, font: boldFont });
  y -= 25;
  protocolBreakdown.forEach(p => drawKV(p.name, formatNum(p.value)));
  y -= 20;

  // Application Stats
  page.drawText('APPLICATION BREAKDOWN', { x: 50, y, size: 16, font: boldFont });
  y -= 25;

  appBreakdown.forEach(app => {
    if (y < 50) {
      page = pdfDoc.addPage([595.28, 841.89]);
      y = 800;
    }
    
    // Draw bar and text
    const pct = ((app.packets / stats.totalPackets) * 100).toFixed(1);
    page.drawText(app.name, { x: 50, y, size: 12, font: boldFont });
    page.drawText(`${formatNum(app.packets)} pkts (${pct}%)`, { x: 180, y, size: 12, font });
    
    // Draw simple bar
    const barWidth = 200 * (app.packets / stats.totalPackets);
    page.drawRectangle({
      x: 340, y: y - 2, width: barWidth, height: 12,
      color: rgb(0.2, 0.6, 1.0),
    });
    
    y -= 20;
  });

  return await pdfDoc.save();
}
