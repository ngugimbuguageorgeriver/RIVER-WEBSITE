// SCROLL EFFECT    .........................................................

window.addEventListener("scroll", () => {
    document.querySelector(".header").classList.toggle("scrolled", window.scrollY > 50);});


// BACK TO TOP EFFECT    .........................................................

const backToTop = document.getElementById("backToTop");

// Show button when scrolled 200px down
window.addEventListener("scroll", () => {
    if (window.scrollY > 200) {
    backToTop.classList.add("show");
    } else {
    backToTop.classList.remove("show");
    }
});

// Smooth scroll back to top
backToTop.addEventListener("click", () => {
    window.scrollTo({
    top: 0,
    behavior: "smooth"
    });
});


// NAVBAR INTERACTIVE EFFECT    .........................................................


