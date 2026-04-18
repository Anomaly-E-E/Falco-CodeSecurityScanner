const { supabase } = require('../config/supabase');
const { detectLanguage, analyzeCode } = require('../services/scanService');


async function analyzeScan(req, res) {
  const userId = req.user.userId;
  let creditDeducted = false;
  let previousCredits = null;

  try {
    const { code } = req.body;

    if (!code || code.trim().length === 0) {
      return res.status(400).json({ error: 'Code is required' });
    }

    const language = detectLanguage(code);

    if (language === 'unknown') {
      return res.status(400).json({
        error: 'Could not detect programming language. Supported: Python, JavaScript, Java, C/C++'
      });
    }

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
        error: 'Not enough credits. You need at least 1 credit to run a scan.',
        credits: user.credits
      });
    }

    previousCredits = user.credits;

    // deduct before the AI call to prevent race conditions
    const { data: updatedUser, error: updateError } = await supabase
      .from('users')
      .update({ credits: user.credits - 1 })
      .eq('id', userId)
      .select('credits')
      .single();

    if (updateError || !updatedUser) {
      return res.status(500).json({ error: 'Failed to process scan. Please try again.' });
    }

    creditDeducted = true;

    const vulnerabilities = await analyzeCode(code, language);

    const { data: scan, error: scanError } = await supabase
      .from('scans')
      .insert({
        user_id: userId,
        code_length: code.length,
        language,
        status: 'completed',
        vulnerabilities_count: vulnerabilities.length,
        scan_result: vulnerabilities
      })
      .select()
      .single();

    if (scanError) {
      console.error('Failed to save scan record:', scanError);
    }

    res.status(200).json({
      message: 'Scan completed',
      scan: {
        id: scan?.id,
        language,
        codeLength: code.length,
        vulnerabilitiesCount: vulnerabilities.length,
        vulnerabilities,
        creditsRemaining: updatedUser.credits,
        scannedAt: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('Scan error:', error);

    // refund the credit if we already deducted it but AI failed
    if (creditDeducted && previousCredits !== null) {
      try {
        await supabase
          .from('users')
          .update({ credits: previousCredits })
          .eq('id', userId);
        console.log('Credit refunded for user:', userId);
      } catch (refundError) {
        console.error('Failed to refund credit:', refundError);
      }
    }

    res.status(500).json({
      error: creditDeducted
        ? 'Scan failed. Your credit has been refunded.'
        : 'An error occurred during scan'
    });
  }
}


async function getScanHistory(req, res) {
  try {
    const userId = req.user.userId;

    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 20));
    const from = (page - 1) * limit;
    const to = from + limit - 1;

    const { data: scans, error, count } = await supabase
      .from('scans')
      .select('id, language, code_length, vulnerabilities_count, status, created_at', { count: 'exact' })
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .range(from, to);

    if (error) {
      return res.status(500).json({ error: 'Failed to fetch scan history' });
    }

    res.status(200).json({
      totalScans: count || 0,
      page,
      limit,
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
    res.status(500).json({ error: 'Failed to fetch scan history' });
  }
}


async function getScanById(req, res) {
  try {
    const userId = req.user.userId;
    const scanId = req.params.id;

    const { data: scan, error } = await supabase
      .from('scans')
      .select('*')
      .eq('id', scanId)
      .eq('user_id', userId) // ensures users can only see their own scans
      .single();

    if (error || !scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    res.status(200).json({
      id: scan.id,
      language: scan.language,
      codeLength: scan.code_length,
      vulnerabilitiesCount: scan.vulnerabilities_count,
      vulnerabilities: scan.scan_result,
      status: scan.status,
      scannedAt: scan.created_at
    });

  } catch (error) {
    console.error('Get scan error:', error);
    res.status(500).json({ error: 'Failed to fetch scan' });
  }
}


module.exports = { analyzeScan, getScanHistory, getScanById };
