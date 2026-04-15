require('dotenv').config();
const { analyzeCode, detectLanguage } = require('./src/services/scanService');

// Java code with a hardcoded credential — a real vulnerability
const vulnerableCode = `System.out.println("password is 000")`;

const language = detectLanguage(vulnerableCode);

console.log('Testing Gemini AI Analysis...\n');
console.log('Code being analyzed:');
console.log(vulnerableCode);
console.log(`Detected language: ${language}`);
console.log('\n' + '='.repeat(60) + '\n');

console.log('Sending to Google Gemini... (this takes 3-5 seconds)\n');

analyzeCode(vulnerableCode, language)
  .then(vulnerabilities => {
    console.log('\n' + '='.repeat(60));
    console.log('SCAN RESULTS:\n');

    if (vulnerabilities.length === 0) {
      console.log('No vulnerabilities found.');
    } else {
      vulnerabilities.forEach((vuln, index) => {
        console.log(`\nVulnerability #${index + 1}:`);
        console.log(`${'─'.repeat(40)}`);
        console.log(`Line:     ${vuln.line}`);
        console.log(`Severity: ${vuln.severity}`);
        console.log(`Type:     ${vuln.type}`);
        console.log(`\nProblem:\n  ${vuln.problem}`);
        console.log(`\nAttack:\n  ${vuln.attack}`);
        console.log(`\nFix:\n  ${vuln.fix}`);
      });
    }

    console.log('\n' + '='.repeat(60));
    console.log('Test complete.\n');
  })
  .catch(error => {
    console.error('Test failed:', error.message);
  });
