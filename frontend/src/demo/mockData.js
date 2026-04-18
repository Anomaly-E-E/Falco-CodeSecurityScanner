export const MOCK_USER = {
  id: 'demo-user',
  email: 'demo@falco.dev',
  credits: 7,
  isVerified: true,
};

export const MOCK_SCAN = {
  id: 'scan-001',
  language: 'python',
  codeLength: 218,
  vulnerabilitiesCount: 3,
  creditsRemaining: 7,
  scannedAt: new Date().toISOString(),
  vulnerabilities: [
    {
      line: 4,
      severity: 'HIGH',
      type: 'SQL Injection',
      problem: 'User input is concatenated directly into a database query. An attacker can manipulate the query to read, modify, or delete data they should not have access to.',
      attack: 'Craft an input like \'OR 1=1-- to bypass authentication checks or append additional statements to extract sensitive rows from the database.',
      fix: `cursor.execute("SELECT * FROM users WHERE name = ?", (username,))`,
    },
    {
      line: 7,
      severity: 'HIGH',
      type: 'Hardcoded Credential',
      problem: 'A password is stored in plain text inside the source code. Anyone who can read this file — including via version control history — can obtain the credential.',
      attack: 'An attacker with repo read access extracts the credential and uses it to authenticate as an administrator without any brute-force attempt.',
      fix: `import os\npassword = os.environ["ADMIN_PASSWORD"]`,
    },
    {
      line: 12,
      severity: 'LOW',
      type: 'Missing Input Validation',
      problem: 'Data from an external source is used without checking its type or length first. Unexpected values can cause crashes or unexpected application behavior downstream.',
      attack: 'Submit an oversized or malformed value to trigger an unhandled exception that leaks a stack trace, revealing internal file paths and library versions.',
      fix: `if not isinstance(value, str) or len(value) > 256:\n    raise ValueError("Invalid input")`,
    },
  ],
};

export const MOCK_HISTORY = [
  {
    id: 'scan-001',
    language: 'python',
    codeLength: 218,
    vulnerabilitiesCount: 3,
    status: 'completed',
    scannedAt: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
  },
  {
    id: 'scan-002',
    language: 'javascript',
    codeLength: 145,
    vulnerabilitiesCount: 1,
    status: 'completed',
    scannedAt: new Date(Date.now() - 18 * 60 * 60 * 1000).toISOString(),
  },
  {
    id: 'scan-003',
    language: 'java',
    codeLength: 312,
    vulnerabilitiesCount: 0,
    status: 'completed',
    scannedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
  },
];
