import { parsePcap } from './pcapAnalyzer.js';
import path from 'path';

async function test() {
  try {
    const res = await parsePcap('../test_dpi.pcap', [], [], []);
    console.log('SUCCESS! Parsed PCAP');
    console.log('Stats:', res.stats);
    console.log('Flows count:', res.flows.length);
    console.log('Apps:', res.appBreakdown.map(a => a.name));
  } catch (e) {
    console.error('FAILED!', e);
  }
}

test();
