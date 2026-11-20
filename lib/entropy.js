/*
 * Shannon entropy helper, shared by the content script, the service worker,
 * and the offline test harness (everything reaches it through self.PSS).
 */
(function () {
  function shannonEntropy(str) {
    if (!str || str.length === 0) return 0;
    const freq = Object.create(null);
    for (let i = 0; i < str.length; i++) {
      const ch = str[i];
      freq[ch] = (freq[ch] || 0) + 1;
    }
    let h = 0;
    for (const ch in freq) {
      const p = freq[ch] / str.length;
      h -= p * Math.log2(p);
    }
    return h;
  }

  self.PSS = self.PSS || {};
  self.PSS.shannonEntropy = shannonEntropy;
})();
