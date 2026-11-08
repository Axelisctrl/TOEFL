
export default async function handler(req, res) {
  const cookies = Object.fromEntries(
    (req.headers.cookie || "")
      .split(";")
      .map(c => c.trim().split("="))
      .filter(c => c.length >= 2)
      .map(([k, ...v]) => [k, decodeURIComponent(v.join("="))])
  );

  const { code, state, error } = req.query;

  if (error) {
    return res.status(400).send("X authorization was denied.");
  }

  if (!code || !state || state !== cookies.x_state || !cookies.x_verifier) {
    return res.status(400).send("Invalid authentication request.");
  }

  const clientId = process.env.X_CLIENT_ID;
  const clientSecret = process.env.X_CLIENT_SECRET;
  const redirectUri = process.env.X_REDIRECT_URI;

  try {
    const credentials = Buffer.from(
      `${clientId}:${clientSecret}`
    ).toString("base64");

    const response = await fetch("https://api.x.com/2/oauth2/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${credentials}`
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: cookies.x_verifier
      })
    });

    const tokens = await response.json();

    if (!response.ok || !tokens.access_token) {
      return res.status(400).send("X token exchange failed.");
    }

    const userResponse = await fetch("https://api.x.com/2/users/me", {
      headers: {
        Authorization: `Bearer ${tokens.access_token}`
      }
    });

    const user = await userResponse.json();

    if (!userResponse.ok) {
      return res.status(400).send("Authentication succeeded, but user lookup failed.");
    }

    res.setHeader("Set-Cookie", [
      "x_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
      "x_verifier=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
    ]);

    return res.status(200).send(
      `X account connected successfully! Welcome, @${user.data.username}. Your connection has been tested, but tokens have not been saved for future use.`
    );

  } catch (err) {
    return res.status(500).send("Authentication failed. Please try again.");
  }
}

