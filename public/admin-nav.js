(() => {
  const body = document.body;
  const modal = document.querySelector('[data-admin-nav]');
  const toggle = document.querySelector('[data-admin-nav-toggle]');

  if (!modal || !toggle) return;

  const closeTargets = Array.from(
    modal.querySelectorAll('[data-admin-nav-close], [data-admin-nav-link]')
  );

  function setOpen(open) {
    body.classList.toggle('admin-nav-open', open);
    modal.classList.toggle('is-open', open);
    modal.setAttribute('aria-hidden', open ? 'false' : 'true');
    toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
  }

  function openNav() {
    setOpen(true);
  }

  function closeNav() {
    setOpen(false);
  }

  toggle.addEventListener('click', () => {
    const isOpen = modal.classList.contains('is-open');
    setOpen(!isOpen);
  });

  closeTargets.forEach((el) => {
    el.addEventListener('click', () => closeNav());
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeNav();
  });

  window.addEventListener('resize', () => {
    if (window.innerWidth > 980) closeNav();
  });

  window.closeAdminNav = closeNav;
  window.openAdminNav = openNav;
})();
