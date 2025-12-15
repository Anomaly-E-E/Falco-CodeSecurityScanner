require('dotenv').config();
//Analyze code for security vulnerabilities using OpenAI API

const { GoogleGenerativeAI } = require('@google/generative-ai');
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: 'models/gemini-flash-lite-latest' });



 // DETECT PROGRAMMING LANGUAGE

function detectLanguage(code) {
    // Convert to lowercase for easier matching
    const lowerCode = code.toLowerCase();
    
    // Python 
    if (lowerCode.includes('def ') || 
        lowerCode.includes('import ') || 
        lowerCode.includes('print(')) {
      return 'python';
    }
    
    // JavaScript/Node.js 
    if (lowerCode.includes('const ') || 
        lowerCode.includes('let ') || 
        lowerCode.includes('var ') ||
        lowerCode.includes('function ') ||
        lowerCode.includes('=> ') ||
        lowerCode.includes('require(') ||
        lowerCode.includes('console.log')) {
      return 'javascript';
    }
    
    // Java 
    if (lowerCode.includes('public class ') || 
        lowerCode.includes('private ') || 
        lowerCode.includes('system.out.println')) {
      return 'java';
    }
    
    // C/C++ 
    if (lowerCode.includes('#include') || 
        lowerCode.includes('printf(') ||
        lowerCode.includes('std::')) {
      return 'c/c++';
    }
    
    // If no match, return unknown
    return 'unknown';
  }



async function analyzeCode(code, language) {
  try {
    console.log(`🤖 Analyzing ${language} code with Google Gemini...`);
    
    // STEP 1: Create the prompt for Gemini
    const prompt = `You are a cybersecurity expert. Analyze this ${language} code for security vulnerabilities.

    For EACH vulnerability found, respond in this EXACT JSON format (no markdown, no code blocks, just raw JSON array):
    [
      {
        "line": <line_number>,
         "severity": "HIGH" | "MEDIUM" | "LOW",
         "type": "vulnerability type (e.g., SQL Injection, XSS, etc.)",
         "problem": "Brief 1-2 sentence description of the problem",
          "attack": "how an attacker can exploit this vulnerability (1-2 sentences)",
          "fix": "How to fix it with code example"
       }
    ]

   IMPORTANT RULES:
   - Only return a JSON ARRAY — no surrounding text, no comments, no code blocks.
   - Every object MUST follow the exact keys and order shown above.
   - If no vulnerabilities are found, return: []
   - Use precise line numbers where vulnerabilities appear.
   - Do NOT invent vulnerabilities — only report real, defensible issues.
   - Fix examples must be valid and secure for the given language.
   - The JSON must always be valid and parseable.
   -Explain the Problem in an easy so people wihtout a security backgroud will be able to understand
   -For how to fix explain is an easy way  
   -For same Vulnerability show togther which all lines have it
   -Do not refer to past scans, think and start fresh 

   Code to analyze:
   ${code}`;

   
   const result = await model.generateContent(prompt);
   const response = await result.response;
   const text = response.text();
    
    console.log('✅ Gemini analysis complete');
    
    //Parse and return
    return parseAIResponse(text);
    
  } catch (error) {
    console.error('❌ Gemini analysis error:', error.message);
    throw new Error('Failed to analyze code: ' + error.message);
  }
}


function parseAIResponse(response) {
  try{
    let cleaned = response.trim();
    cleaned = cleaned.replace(/```json\s*/g, '');
    cleaned = cleaned.replace(/```\s*/g, '');

    const startIndex = cleaned.indexOf('[');
    const endIndex = cleaned.lastIndexOf(']');

    if (startIndex === -1 || endIndex === -1) {
      console.log('No JSON array found in response');
      return [];
    }

    const jsonStr = cleaned.substring(startIndex, endIndex + 1);
    const vulnerabilities = JSON.parse(jsonStr);
    console.log(`Found ${vulnerabilities.length} vulnerabilities`);
    return vulnerabilities;
  } catch (error) {
    console.error('❌ Failed to parse AI response:', error.message);
    console.log('Response was:', response.substring(0, 200));
    return [];
  }
}

  



module.exports = {
  detectLanguage,
  analyzeCode
};


