/**
 * Secure Lens AI API Client
 * Centralized API client for all Secure Lens AI API calls.
 * Handles authentication, token management, and error handling.
 */

// Auto-detect API URL: use localhost in development, relative path in production
const API_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
  ? 'http://localhost:5000/api'
  : (window.SECURE_LENS_API_URL || `${window.location.origin}/api`);
const TOKEN_KEY = 'seculens_token';
const USER_KEY = 'seculens_user';

/* ─── Token Management ─── */

function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

function setToken(token) {
  if (token) localStorage.setItem(TOKEN_KEY, token);
}

function removeToken() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

function getStoredUser() {
  try {
    const u = localStorage.getItem(USER_KEY);
    return u ? JSON.parse(u) : null;
  } catch (e) { return null; }
}

function isLoggedIn() {
  return !!getToken();
}

/**
 * Redirect to login page if not authenticated.
 * Call at the top of every protected page.
 */
function requireAuth() {
  if (!isLoggedIn()) {
    window.location.href = '/login.html';
    return false;
  }
  return true;
}

/* ─── Generic API Call ─── */

async function apiCall(method, endpoint, data = null, isFormData = false) {
  const url = `${API_URL}${endpoint}`;
  const token = getToken();

  const headers = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (!isFormData && data !== null) headers['Content-Type'] = 'application/json';

  const options = { method, headers };
  if (data !== null) {
    options.body = isFormData ? data : JSON.stringify(data);
  }

  const response = await fetch(url, options);

  // 401 → token expired or invalid
  if (response.status === 401) {
    removeToken();
    window.location.href = '/login.html';
    return null;
  }

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || errorData.message || `HTTP ${response.status}: ${response.statusText}`);
  }

  return response.json();
}

/* ─── Authentication ─── */

async function login(username, password) {
  const response = await apiCall('POST', '/auth/login', { username, password });
  if (response && response.access_token) {
    setToken(response.access_token);
    if (response.user) localStorage.setItem(USER_KEY, JSON.stringify(response.user));
  }
  return response;
}

async function register(username, password) {
  return apiCall('POST', '/auth/register', { username, password });
}

function logout() {
  removeToken();
  window.location.href = '/login.html';
}

async function getMe() {
  return apiCall('GET', '/auth/me');
}

/* ─── Analysis Endpoints ─── */

async function getAnalyses() {
  return apiCall('GET', '/analyses');
}

async function getAnalysis(id) {
  return apiCall('GET', `/analyses/${id}`);
}

async function getAnalysisLogs(id, page = 1) {
  return apiCall('GET', `/analyses/${id}/logs?page=${page}`);
}

/* ─── File Upload ─── */

async function uploadFile(formData) {
  return apiCall('POST', '/upload', formData, true);
}

/* ─── Contact ─── */

async function submitContact(data) {
  return apiCall('POST', '/contact', data);
}

/* ─── Account ─── */

async function getAccountStats() {
  return apiCall('GET', '/account/stats');
}

/* ─── Expose Globally ─── */

if (!window.SecuLens) window.SecuLens = {};

window.SecuLens.api = {
  API_URL,
  getToken, setToken, removeToken, getStoredUser, isLoggedIn,
  requireAuth,
  apiCall,
  login, register, logout, getMe,
  getAnalyses, getAnalysis, getAnalysisLogs,
  uploadFile,
  submitContact,
  getAccountStats
};
