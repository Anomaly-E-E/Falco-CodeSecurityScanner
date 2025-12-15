const { supabase } = require('../config/supabase');
const { detectLanguage, analyzeCode } = require('../services/scanService');


async function analyzeScan(req, res){
    try{
        const {code} = req.body;
        const userId = req.user.userId;
        console.log(`🔍 Scan request from user: ${req.user.email}`);

        if (!code) {
            return res.status(400).json({ 
              error: 'Code is required' 
            });
        }
        
        //Set Max Code length
        const maxLength = 400;
        if (code.length > maxLength) {
            return res.status(400).json({ 
                error: `Code too long. Maximum ${maxLength} characters allowed.` 
            });
        }

        //Check if code is empty
        if (code.trim().length === 0) {
            return res.status(400).json({ 
              error: 'Code cannot be empty' 
            });
        }
          
        console.log(`Code length: ${code.length} characters`);

        //Check user has credits
        const {data: user, error: userError } = await supabase
          .from ('users')
          .select('credits')
          .eq('id', userId)
          .single();

        if (userError || !user) {
            return res.status(500).json({ 
              error: 'Failed to fetch user data' 
            });
        }

        if (user.credits < 1) {
            return res.status(402).json({ 
              error: 'Insufficient credits. Please purchase more credits to continue scanning.',
              credits: user.credits
            });
        }

        console.log(`User has ${user.credits} credits`);

        //Detect Language
        const language = detectLanguage(code);
        console.log(`Detected language: ${language}`);

        if (language == 'unknown'){
          return res.status(400).json({ 
            error: 'Could not detect programming language. Supported: Python, JavaScript, Java, C/C++, PHP, Ruby, Go' 
          });
        }

        //Analyze code with AI
        console.log(`Starting AI analysis...`);
        const vulnerabilities = await analyzeCode(code, language);
        

        //Deduct 1 credit from user
        const newCredits = user.credits - 1;
        const { data: updatedUser, error: updateError } = await supabase
        .from('users')
        .update({ credits: newCredits })
        .eq('id', userId)
        .select('credits')
        .single();
        
        if (updateError || !updatedUser) {
          console.error('Failed to deduct credit:', updateError);
          return res.status(500).json({ 
            error: 'Failed to process scan. Credit not deducted.' 
          });
        }
        console.log(`✅ Credit deducted. Remaining: ${updatedUser.credits}`);

        const { data: scan, error: scanError} = await supabase
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
          
          console.log(`Scan saved with ID: ${scan?.id}`);
          
          //Return results
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
          }, null, 2);

    }catch (error) {
        console.error('❌ Scan error:', error);
        res.status(500).json({ 
          error: 'An error occurred during scan' 
        });
      }
}

async function getScanHistory(req, res) {
  try{

    const userId = req.user.userId;
    console.log(`Fetching scan history for user: ${req.user.email}`);

    // Query all scans for this user, ordered by newest first
    const { data: scans, error } = await supabase
      .from('scans')
      .select('id, language, code_length, vulnerabilities_count, status, created_at')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });
    
    if (error) {
      console.error('Database error:', error);
      return res.status(500).json({ 
        error: 'Failed to fetch scan history' 
      });
    }
    
    console.log(`Found ${scans.length} scans`);
    
    // Return formatted response
    res.status(200).json({
      totalScans: scans.length,
      scans: scans.map(scan => ({
        id: scan.id,
        language: scan.language,
        codeLength: scan.code_length,
        vulnerabilitiesCount: scan.vulnerabilities_count,
        status: scan.status,
        scannedAt: scan.created_at
      },null, 2))
    });
    
  } catch (error) {
    console.error(' History fetch error:', error);
    res.status(500).json({ 
      error: 'An error occurred fetching history' 
    });
  }
}
  


module.exports = {
  analyzeScan,
  getScanHistory
};