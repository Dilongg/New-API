import express from 'express'; 
import crypto from 'crypto';

const app = express();

app.use(express.json());

// ==================================== 
// SERVICE ACCOUNT 
// ==================================== 

const serviceAccount = { 
  client_email: process.env .GOOGLE_CLIENT_EMAIL, 
  private_key: process.env .GOOGLE_PRIVATE_KEY .replace(/\\n/g, '\n') 
}; 

// ==================================== 
// BASE64URL 
// ==================================== 

function base64url(source) { 
  let encoded = 
    Buffer 
    .from(JSON.stringify(source)) 
    .toString('base64'); 
  return encoded 
    .replace(/=/g, '') 
    .replace(/\+/g, '-') 
    .replace(/\//g, '_'); 
} 

// ==================================== 
// TOKEN 
// ==================================== 

app.get('/token', async (req, res) => { 
  try { 
    
    const now = 
      Math.floor(Date.now() / 1000); 
    const header = { 
      alg: 'RS256', 
      typ: 'JWT' 
    }; 
    
    const payload = { 
      iss: 
        serviceAccount.client_email,
      
      scope: 
        'https://www.googleapis.com/auth/spreadsheets', 
      
      aud: 
        'https://oauth2.googleapis.com/token', 
      
      exp: now + 3600, 
      
      iat: 
        now 
    }; 
    
    const unsignedToken = 
      `${base64url(header)}.${base64url(payload)}`; 
    
    const signature = crypto 
      .createSign('RSA-SHA256') 
      .update(unsignedToken) 
      .sign( 
        serviceAccount.private_key, 
            'base64' 
           ) 
      .replace(/=/g, '') 
      .replace(/\+/g, '-') 
      .replace(/\//g, '_'); 
    
    const jwt = 
      `${unsignedToken}.${signature}`; 
    
    const response = await fetch( 
      'https://oauth2.googleapis.com/token', 
      { 
        method: 'POST', 
        headers: { 
          'Content-Type': 
            'application/x-www-form-urlencoded' 
        }, 
        
        body: 
          'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' + 
          '&assertion=' + 
          encodeURIComponent(jwt) 
      }
    ); 
    
    const data = 
      await response.json(); 
    res.json(data); 
  } 
  catch (err) { 
    
    res.status(500).json({ 
      error: err.message 
    }); 
  } 
}); 


// ==================================== 
// START 
// ==================================== 

const PORT = 
  process.env.PORT || 3000; 
app.listen(PORT, () => { 
  console.log( 
    `Servidor rodando na porta ${PORT}`
  ); 
});
