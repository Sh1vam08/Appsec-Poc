// Basic Vanilla JS Router
const routes = {
    '': homeView,
    '#login': loginView,
    '#search': searchView
};

function router() {
    const app = document.getElementById('app');
    const hash = window.location.hash;
    const view = routes[hash] || notFoundView;
    app.innerHTML = view();
}

function homeView() {
    return `
        <h1>Welcome to ShopSphere SPA</h1>
        <p>This is a single page application to test DAST crawlers.</p>
        <nav>
            <a href="#login">Login</a> | 
            <a href="#search">Search Users</a>
        </nav>
    `;
}

function loginView() {
    return `
        <h1>Login</h1>
        <form id="loginForm" onsubmit="doLogin(event)">
            <input type="text" id="username" placeholder="Username" />
            <button type="submit">Submit</button>
        </form>
        <p id="loginResult"></p>
        <a href="#">Back to Home</a>
    `;
}

function searchView() {
    return `
        <h1>Search Users</h1>
        <form id="searchForm" onsubmit="doSearch(event)">
            <input type="text" id="query" placeholder="LDAP Username" />
            <button type="submit">Search</button>
        </form>
        <p id="searchResult"></p>
        <a href="#">Back to Home</a>
    `;
}

function notFoundView() {
    return '<h1>404 - Not Found</h1><a href="#">Home</a>';
}

window.addEventListener('hashchange', router);
window.addEventListener('load', router);

// API Calls that the DAST scanner should discover and invoke
function doLogin(e) {
    e.preventDefault();
    const user = document.getElementById('username').value;
    // Calls the vulnerable JWT endpoint
    fetch(`/api/v1/auth/jwt/login?username=${encodeURIComponent(user)}`, {
        method: 'POST'
    })
    .then(r => r.text())
    .then(text => document.getElementById('loginResult').innerText = text);
}

function doSearch(e) {
    e.preventDefault();
    const query = document.getElementById('query').value;
    // Calls the vulnerable LDAP endpoint
    fetch(`/api/v1/users/search/vulnerable?username=${encodeURIComponent(query)}`)
    .then(r => r.text())
    .then(text => document.getElementById('searchResult').innerText = text);
}
