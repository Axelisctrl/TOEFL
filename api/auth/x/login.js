
const crypto = require("crypto");

module.exports = function handler(req, res) {
  const clientId = process.env.X_CLIENT_ID;
  const redirectUri = process.env.X_REDIRECT_URI;

  if (!clientId || !redirectUri) {
    return res.status(500).send("Missing X authentication settings.");
  }

  const state = "s" + crypto.randomBytes(24).toString("hex");
  const codeVerifier = crypto.randomBytes(32).toString("base64url");

  const codeChallenge = crypto
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
    state: state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256"
  });

  return res.redirect(
    "https://x.com/i/oauth2/authorize?" + params.toString()
  );
};
