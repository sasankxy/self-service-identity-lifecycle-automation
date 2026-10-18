/* IdentityOS — mobile navigation drawer + collapsible topbar search.
   Works with the markup in index.html (#menu-btn, #sidebar-backdrop,
   #search-toggle). Does not touch app.js routing: it only listens for clicks. */
(function () {
  'use strict';

  var mq = window.matchMedia('(max-width: 1024px)');
  var body = document.body;
  var sidebar = document.getElementById('sidebar');
  var menuBtn = document.getElementById('menu-btn');
  var backdrop = document.getElementById('sidebar-backdrop');
  var topbar = document.querySelector('.topbar');
  var searchBtn = document.getElementById('search-toggle');
  var searchInput = document.getElementById('global-search');
  if (!sidebar || !menuBtn) return;

  function setNav(open) {
    open = !!open && mq.matches;
    sidebar.classList.toggle('open', open);
    body.classList.toggle('nav-open', open);
    menuBtn.setAttribute('aria-expanded', String(open));
    menuBtn.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
    if (open) {
      var target = sidebar.querySelector('.nav-item.active') || sidebar.querySelector('.nav-item');
      if (target) target.focus();
    }
  }

  menuBtn.addEventListener('click', function () {
    setNav(!sidebar.classList.contains('open'));
  });
  if (backdrop) backdrop.addEventListener('click', function () { setNav(false); });

  // Picking a page (or signing out) closes the drawer
  sidebar.addEventListener('click', function (e) {
    if (e.target.closest('.nav-item, #logout-btn')) setNav(false);
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && sidebar.classList.contains('open')) {
      setNav(false);
      menuBtn.focus();
    }
  });

  // Rotating a tablet / resizing to desktop resets the drawer state
  var onChange = function () { if (!mq.matches) setNav(false); };
  if (mq.addEventListener) mq.addEventListener('change', onChange);
  else if (mq.addListener) mq.addListener(onChange);

  if (searchBtn && topbar) {
    searchBtn.addEventListener('click', function () {
      var openSearch = topbar.classList.toggle('search-open');
      searchBtn.setAttribute('aria-expanded', String(openSearch));
      if (openSearch && searchInput) searchInput.focus();
    });
  }
})();
