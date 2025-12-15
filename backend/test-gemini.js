require('dotenv').config();
const { analyzeCode } = require('./src/services/scanService');

// Vulnerable Python code with SQL injection
const vulnerableCode = `System.out.println("password is 000")`;

console.log('🧪 Testing Gemini AI Analysis...\n');
console.log('Code being analyzed:');
console.log(vulnerableCode);
console.log('\n' + '='.repeat(60) + '\n');

console.log('⏳ Sending to Google Gemini... (this takes 3-5 seconds)\n');

analyzeCode(vulnerableCode, 'python')
  .then(vulnerabilities => {
    console.log('\n' + '='.repeat(60));
    console.log('📋 SCAN RESULTS:\n');
    
    if (vulnerabilities.length === 0) {
      console.log('✅ No vulnerabilities found!');
    } else {
      vulnerabilities.forEach((vuln, index) => {
        console.log(`\n🔴 Vulnerability #${index + 1}:`);
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        console.log(`📍 Line: ${vuln.line}`);
        console.log(`⚠️  Severity: ${vuln.severity}`);
        console.log(`🏷️  Type: ${vuln.type}`);
        console.log(`\n🔍 Problem:\n   ${vuln.problem}`);
        console.log(`\n💀 What Attacker Can Do:\n   ${vuln.attack}`);
        console.log(`\n✅ How to Fix:\n   ${vuln.fix}`);
      });
    }
    
    console.log('\n' + '='.repeat(60));
    console.log('\n✅ Test complete! Gemini AI scanning works!\n');
  })
  .catch(error => {
    console.error('\n❌ Test failed:', error.message);
    console.error('Full error:', error);
  });