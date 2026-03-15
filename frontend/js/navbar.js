/**
 * Secure Lens AI Navbar
 * Dynamic navigation bar with auth-aware rendering.
 * Shows login/register links when logged out, user info + logout when logged in.
 */

function getCurrentPage() {
  const pathname = window.location.pathname;
  const filename = pathname.split('/').pop() || 'index.html';
  return filename.replace('.html', '') || 'home';
}

function isActivePage(page) {
  const cp = getCurrentPage();
  return cp === page || (page === 'home' && cp === 'index');
}

function getBrandIcon() {
  return `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
}

/**
 * Build navbar HTML based on auth state.
 */
function createNavbarHTML() {
  const loggedIn = window.SecuLens && window.SecuLens.api && window.SecuLens.api.isLoggedIn();
  const user = loggedIn && window.SecuLens.api.getStoredUser ? window.SecuLens.api.getStoredUser() : null;
  const username = (user && user.username) ? user.username : 'User';
  const initial = username.charAt(0).toUpperCase();

  const rightSection = loggedIn ? `
    <div class="navbar-user">
      <div id="navbar-avatar" class="navbar-user-avatar">${initial}</div>
      <div style="display:flex;flex-direction:column;">
        <span id="navbar-username" class="navbar-user-name">${username}</span>
      </div>
      <a href="/account.html" class="navbar-account-link" style="text-decoration:none;color:#8b95b0;font-weight:500;padding:0.4rem 0.8rem;border-radius:6px;transition:all 0.2s ease;font-size:0.9rem;">Account</a>
      <button class="navbar-logout-btn" id="logout-btn">Logout</button>
    </div>
  ` : `
    <div class="navbar-user" style="gap:10px;">
      <a href="/login.html" style="text-decoration:none;color:#14b8a6;font-weight:600;padding:8px 20px;border:1px solid rgba(20,184,166,0.4);border-radius:8px;font-size:0.9rem;transition:all 0.2s ease;">Sign In</a>
    </div>
  `;

  return `
    <nav class="navbar">
      <a href="/index.html" class="navbar-brand" style="text-decoration:none;">
        <div class="navbar-brand-icon">${getBrandIcon()}</div>
        <span>Secure Lens AI</span>
      </a>
      <div class="navbar-nav">
        <a href="/index.html" class="navbar-nav-item ${isActivePage('home') ? 'active' : ''}" style="text-decoration:none;">Home</a>
        <a href="/analysis.html" class="navbar-nav-item ${isActivePage('analysis') ? 'active' : ''}" style="text-decoration:none;">Analysis</a>
        <a href="/contact.html" class="navbar-nav-item ${isActivePage('contact') ? 'active' : ''}" style="text-decoration:none;">Contact Us</a>
      </div>
      ${rightSection}
    </nav>
  `;
}

/**
 * Refresh the user section with latest data from /auth/me.
 */
async function loadUserInfo() {
  try {
    if (!window.SecuLens || !window.SecuLens.api || !window.SecuLens.api.isLoggedIn()) return;
    const user = await window.SecuLens.api.getMe();
    if (user && user.username) {
      localStorage.setItem('seculens_user', JSON.stringify(user));
      const avatarEl = document.getElementById('navbar-avatar');
      const nameEl = document.getElementById('navbar-username');
      if (avatarEl) avatarEl.textContent = user.username.charAt(0).toUpperCase();
      if (nameEl) nameEl.textContent = user.username;
    }
  } catch (err) {
    console.warn('Could not load user info:', err.message);
  }
}

function handleLogout() {
  if (window.SecuLens && window.SecuLens.api) {
    window.SecuLens.api.logout();
  } else {
    localStorage.removeItem('seculens_token');
    localStorage.removeItem('seculens_user');
    window.location.href = '/login.html';
  }
}

function initNavbar() {
  const container = document.getElementById('navbar-container');
  if (!container) return;

  container.innerHTML = createNavbarHTML();

  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', (e) => { e.preventDefault(); handleLogout(); });
  }

  // Async refresh user info from backend
  loadUserInfo();
}

if (!window.SecuLens) window.SecuLens = {};
window.SecuLens.navbar = { init: initNavbar, loadUserInfo, handleLogout, getCurrentPage, isActivePage };

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initNavbar);
} else {
  initNavbar();
}
