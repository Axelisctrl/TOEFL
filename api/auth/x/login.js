
import crypto from "crypto";

export default function handler(req, res) {
  const clientId = process.env.X_CLIENT_ID;
  const redirectUri = process.env.X_REDIRECT_URI;

  if (!clientId || !redirectUri) {
    return res.status(500).send("X authentication credentials are missing.");
  }

  const state = "s" + crypto.randomUUID();

  const codeVerifier = crypto.randomBytes(32).toString("base64url");

  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");

  const cookies = [
    `x_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`,
    `x_verifier=${codeVerifier}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`
  ];

  res.setHeader("Set-Cookie", cookies);

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
}
