document.addEventListener('DOMContentLoaded',function(){
  const btn = document.getElementById('menuBtn');
  const nav = document.querySelector('.nav-links');
  if(btn){
    btn.addEventListener('click',()=>{
      if(nav.style.display==='flex') nav.style.display='none';
      else nav.style.display='flex';
    });
  }
  
const y = document.getElementById('year');
if(y) y.textContent = new Date().getFullYear();

window.handleForm = function(e){
  e.preventDefault();
  alert('Demo: form submitted. Connect to Formspree or Netlify for production.');
  e.target.reset();
}
});