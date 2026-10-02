// Where the relay (server.js) runs. Empty means "the server that sent this page"
// (npm start locally, or the Render URL itself). On GitHub Pages the page is
// static, so it points at the Render relay. If you change it, update the CSP in index.html too.
window.WWH_CONFIG = {
  relay: location.hostname.endsWith('github.io') ? "https://while-we-here.onrender.com" : '',
  repo: "https://github.com/politejackal/while-we-here",
};
