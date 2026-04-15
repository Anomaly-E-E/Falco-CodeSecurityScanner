const { supabase } = require('../config/supabase');
const { detectLanguage, analyzeCode } = require('../services/scanService');


async function analyzeScan(req, res) {
  try {
    const { code } = req.body;
    const userId = req.user.userId;

    if (!code) {
      return res.status(400).json({ error: 'Code is required' });
    }

    // Empty check before length check
    if (code.trim().length === 0) {
      return res.status(400).json({ error: 'Code cannot be empty' });
    }

    if (code.length > 400) {
      return res.status(400).json({ error: 'Code too long. Maximum 400 characters allowed.' });
    }

    const language = detectLanguage(code);

    if (language === 'unknown') {
      return res.status(400).json({
        error: 'Could not detect programming language. Supported: Python, JavaScript, Java, C/C++'
      });
    }

    // Fetch user credits
    const { data: user, error: userError } = await supabase
      .from('users')
      .select('credits')
      .eq('id', userId)
      .single();

    if (userError || !user) {
      return res.status(500).json({ error: 'Failed to fetch user data' });
    }

    if (user.credits < 1) {
      return res.status(402).json({
        error: 'Insufficient credits. Please purchase more credits to continue scanning.',
        credits: user.credits
      });
    }

    // Deduct credit before the AI call so concurrent requests can't both slip through
    const { data: updatedUser, error: updateError } = await supabase
      .from('users')
      .update({ credits: user.credits - 1 })
      .eq('id', userId)
      .select('credits')
      .single();

    if (updateError || !updatedUser) {
      return res.status(500).json({ error: 'Failed to process scan. Please try again.' });
    }

    const vulnerabilities = await analyzeCode(code, language);

    const { data: scan, error: scanError } = await supabase
      .from('scans')
      .insert({
        user_id: userId,
        code_length: code.length,
        language: language,
        status: 'completed',
        vulnerabilities_count: vulnerabilities.length,
        scan_result: vulnerabilities
      })
      .select()
      .single();

    if (scanError) {
      console.error('Failed to save scan:', scanError);
    }

    res.status(200).json({
      message: 'Scan completed successfully',
      scan: {
        id: scan?.id,
        language: language,
        codeLength: code.length,
        vulnerabilitiesCount: vulnerabilities.length,
        vulnerabilities: vulnerabilities,
        creditsRemaining: updatedUser.credits,
        scannedAt: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({ error: 'An error occurred during scan' });
  }
}


async function getScanHistory(req, res) {
  try {
    const userId = req.user.userId;

    const { data: scans, error } = await supabase
      .from('scans')
      .select('id, language, code_length, vulnerabilities_count, status, created_at')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(50);

    if (error) {
      return res.status(500).json({ error: 'Failed to fetch scan history' });
    }

    res.status(200).json({
      totalScans: scans.length,
      scans: scans.map(scan => ({
        id: scan.id,
        language: scan.language,
        codeLength: scan.code_length,
        vulnerabilitiesCount: scan.vulnerabilities_count,
        status: scan.status,
        scannedAt: scan.created_at
      }))
    });

  } catch (error) {
    console.error('History fetch error:', error);
    res.status(500).json({ error: 'An error occurred fetching history' });
  }
}


module.exports = { analyzeScan, getScanHistory };
