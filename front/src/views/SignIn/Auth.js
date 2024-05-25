export function login(token,user) {
    localStorage.setItem('token',token);
    localStorage.setItem('user',user);
  }

  
  export function logout() {
    localStorage.clear();
  }
  
  export function getUser() {
    return localStorage.getItem('user');
  }
  export function getToken() {
    return localStorage.getItem('token');
  }
  
  export function isAuthenticated() {
    return getToken() !== null;
  }