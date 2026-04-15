require('dotenv').config();

const { GoogleGenerativeAI } = require('@google/generative-ai');

if (!process.env.GEMINI_API_KEY) {
  throw new Error('Missing GEMINI_API_KEY environment variable');
}

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: 'models/gemini-flash-lite-latest' });


function detectLanguage(code) {
  const lower = code.toLowerCase();

  // C/C++ checked first — #include is unambiguous
  if (lower.includes('#include') || lower.includes('printf(') || lower.includes('std::')) {
    return 'c/c++';
  }

  // Java — check before JS since 'import' appears in both
  if (lower.includes('public class ') || lower.includes('system.out.println') || lower.includes('private ')) {
    return 'java';
  }

  // Python — print( is distinct enough after ruling out C/Java
  if (lower.includes('def ') || lower.includes('print(')) {
    return 'python';
  }

  // JavaScript / Node.js
  if (lower.includes('const ') || lower.includes('let ') || lower.includes('var ') ||
      lower.includes('function ') || lower.includes('=> ') ||
      lower.includes('require(') || lower.includes('console.log')) {
    return 'javascript';
  }

  return 'unknown';
}


async function analyzeCode(code, language) {
  if (!language) {
    language = detectLanguage(code);
  }

  if (language === 'unknown') {
    throw new Error('Could not detect programming language. Supported: Python, JavaScript, Java, C/C++');
  }

  const prompt = `You are a cybersecurity expert. Analyze this ${language} code for security vulnerabilities.

For EACH vulnerability found, respond in this EXACT JSON format (no markdown, no code blocks, just raw JSON array):
[
  {
    "line": <line_number>,
    "severity": "HIGH" | "MEDIUM" | "LOW",
    "type": "vulnerability type (e.g., SQL Injection, XSS, etc.)",
    "problem": "Plain-language description anyone can understand, not just security experts",
    "attack": "How an attacker could exploit this (1-2 sentences)",
    "fix": "How to fix it, with a code example"
  }
]

Rules:
- Return only a valid JSON array — no surrounding text, no code blocks.
- If no vulnerabilities are found, return: []
- Use precise line numbers where the vulnerability appears.
- Only report real, defensible issues. Do not invent vulnerabilities.
- Group the same vulnerability type across multiple lines into one entry.
- Do not refer to previous scans — treat each scan independently.

Code to analyze:
${code}`;

  try {
    const result = await model.generateContent(prompt);
    const text = result.response.text();
    return parseAIResponse(text);
  } catch (error) {
    throw new Error('Failed to analyze code: ' + error.message);
  }
}


function parseAIResponse(response) {
  try {
    const cleaned = response.trim().replace(/```(?:json)?\s*/g, '');

    const startIndex = cleaned.indexOf('[');
    const endIndex = cleaned.lastIndexOf(']');

    if (startIndex === -1 || endIndex === -1) {
      return [];
    }

    return JSON.parse(cleaned.substring(startIndex, endIndex + 1));
  } catch (error) {
    console.error('Failed to parse AI response:', error.message);
    return [];
  }
}


module.exports = { detectLanguage, analyzeCode };
