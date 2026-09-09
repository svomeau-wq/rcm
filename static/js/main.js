document.addEventListener('DOMContentLoaded', function () {
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) {
      if (e.isIntersecting) {
        e.target.classList.add('in');
        io.unobserve(e.target);
      }
    });
  }, { threshold: 0.12 });
  document.querySelectorAll('.reveal').forEach(function (el) { io.observe(el); });

  var heroVisual = document.querySelector('[data-parallax]');
  if (heroVisual) {
    window.addEventListener('scroll', function () {
      heroVisual.style.transform = 'translateY(' + (window.scrollY * -0.06) + 'px)';
    }, { passive: true });
  }

  var refresh = document.getElementById('captcha-refresh-button');
  if (refresh) {
    refresh.addEventListener('click', function () {
      var img = document.getElementById('captcha-image');
      img.src = '/captcha/image?ts=' + Date.now();
    });
  }
});
