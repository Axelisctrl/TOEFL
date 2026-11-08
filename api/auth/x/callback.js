
module.exports = async function handler(req, res) {
  const cookies = {};

  (req.headers.cookie || "").split(";").forEach(item => {
    const parts = item.trim().split("=");
    const key = parts.shift();
    if (key) cookies[key] = decodeURIComponent(parts.join("="));
  });

  const code = req.query.code;
  const state = req.query.state;
  const error = req.query.error;

  if (error) {
    return res.status(400).send("X authorization was denied.");
  }

  if (
    !code ||
    !state ||
    state !== cookies.x_state ||
    !cookies.x_verifier
  ) {
    return res.status(400).send("Invalid authentication request.");
  }

  const clientId = process.env.X_CLIENT_ID;
  const clientSecret = process.env.X_CLIENT_SECRET;
  const redirectUri = process.env.X_REDIRECT_URI;

  if (!clientId || !clientSecret || !redirectUri) {
    return res.status(500).send("Missing X authentication settings.");
  }

  try {
    const credentials = Buffer.from(
      clientId + ":" + clientSecret
    ).toString("base64");

    const tokenResponse = await fetch(
      "https://api.x.com/2/oauth2/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: "Basic " + credentials
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code,
          redirect_uri: redirectUri,
          code_verifier: cookies.x_verifier
        })
      }
    );

    const tokens = await tokenResponse.json();

    if (!tokenResponse.ok || !tokens.access_token) {
      console.error("X token exchange failed:", tokens);
      return res.status(400).send("X token exchange failed.");
    }

    const userResponse = await fetch(
      "https://api.x.com/2/users/me",
      {
        headers: {
          Authorization: "Bearer " + tokens.access_token
        }
      }
    );

    const user = await userResponse.json();

    if (!userResponse.ok || !user.data) {
      return res.status(400).send("X account verification failed.");
    }

    res.setHeader("Set-Cookie", [
      "x_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
      "x_verifier=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
    ]);

    return res.status(200).send(
      "Successfully connected to X! Welcome, @" +
      user.data.username +
      ". This was a test; your tokens have not been saved."
    );

  } catch (err) {
    console.error("X authentication error:", err);
    return res.status(500).send("X authentication failed.");
  }
};
