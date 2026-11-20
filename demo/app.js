/*
 * Demo bundle for the Passive Secret Scanner. All values are fake.
 * Exercises the external-JS, storage, and API-response paths.
 */
(function () {
  const authToken =
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vLXVzZXIiLCJyb2xlIjoiYWRtaW4ifQ.7mYw3sD9kQ1xV2bN4pR6tL8cJ0hF5gA2zX9vB3nM1qK";

  const settings = {
    password: "Xk9mQv2Lp7Rt4Wz8",
    safePlaceholder: "YOUR_API_KEY_HERE_1234567890",
  };

  try {
    // Built at runtime so the literal only exists in storage, not in this file.
    const storageValue = ["Nq7Rt2Wx9Zc4Vb8", "Ml3Kp"].join("");
    localStorage.setItem("demoConfig", JSON.stringify({ apiKey: storageValue }));
  } catch (_) {
    /* storage may be blocked */
  }

  fetch("api.json")
    .then((response) => response.json())
    .then((data) => {
      window.__demoApi = data;
    })
    .catch(() => {});

  window.__demoConfig = { authToken, settings };
})();
