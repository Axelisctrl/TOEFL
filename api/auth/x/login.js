
export default function handler(req, res) {
  const clientId = process.env.X_CLIENT_ID;
  const redirectUri = process.env.X_REDIRECT_URI;

  if (!clientId || !redirectUri) {
    return res.status(500).send("X authentication is not configured.");
  }

  const state = crypto.randomUUID();
  const codeVerifier = crypto.randomUUID() + crypto.randomUUID();

  const cryptoModule = require("crypto");
  const challenge = cryptoModule
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");

  res.setHeader("Set-Cookie", [
    `x_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`,
    `x_verifier=${codeVerifier}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`
  ]);

  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: "tweet.read users.read tweet.write offline.access",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256"
  });

  return res.redirect(
    "https://twitter.com/i/oauth2/authorize?" + params.toString()
  );
}

