async function getToken() {
  const res = await fetch('/csrf-token');
  const data = await res.json();
  return data.csrfToken;
}

async function send(url, body) {
  const token = await getToken();
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
    body: JSON.stringify(body)
  });
  return res.json();
}

// SIGNUP
const sForm = document.getElementById('signupForm');
if (sForm) {
  sForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = await send('/signup', {
      username: username.value,
      password: password.value
    });
    msg.innerText = res.message;
    if (res.message === 'Signup successful') {
      setTimeout(() => (window.location.href = 'index.html'), 800);
    }
  });
}

// LOGIN
const lForm = document.getElementById('loginForm');
if (lForm) {
  lForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = await send('/login', {
      username: username.value,
      password: password.value
    });
    msg.innerText = res.message;
    if (res.message === 'Login successful') {
      setTimeout(() => (window.location.href = 'index.html'), 800);
    }
  });
}

// WELCOME PAGE
if (window.location.pathname.endsWith('index.html')) {
  fetch('/api/welcome')
    .then(r => r.json())
    .then(d => {
      if (d.message.startsWith('Welcome')) {
        document.getElementById('welcomeText').innerText = d.message;
      } else {
        window.location.href = 'login.html';
      }
    });

  logoutBtn.addEventListener('click', async () => {
    const token = await getToken();
    await fetch('/logout', {
      method: 'POST',
      headers: { 'X-CSRF-Token': token }
    });
    window.location.href = 'login.html';
  });
}
