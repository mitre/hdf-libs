(function () {
  'use strict';
  var slice = Array.prototype.slice;
  var root = document.documentElement;
  var themeKey = 'hdf-report-theme';

  function all(selector) {
    return slice.call(document.querySelectorAll(selector));
  }

  // Theme: the reader's choice wins over the system setting and is remembered.
  var toggle = document.getElementById('theme-toggle');

  function systemDark() {
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  }

  function currentTheme() {
    var chosen = root.getAttribute('data-theme');
    if (chosen === 'dark' || chosen === 'light') {
      return chosen;
    }
    return systemDark() ? 'dark' : 'light';
  }

  function showTheme() {
    var dark = currentTheme() === 'dark';
    toggle.textContent = dark ? 'Light mode' : 'Dark mode';
    toggle.setAttribute('aria-label', dark ? 'Switch to light mode' : 'Switch to dark mode');
  }

  function remember(theme) {
    try {
      window.localStorage.setItem(themeKey, theme);
    } catch (ignore) {
      return;
    }
  }

  function recall() {
    try {
      return window.localStorage.getItem(themeKey);
    } catch (ignore) {
      return null;
    }
  }

  var saved = recall();
  if (saved === 'dark' || saved === 'light') {
    root.setAttribute('data-theme', saved);
  }
  toggle.addEventListener('click', function () {
    var next = currentTheme() === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    remember(next);
    showTheme();
  });
  showTheme();

  // Print the whole report, in the light palette, whatever is open on screen.
  var beforePrint = null;
  window.addEventListener('beforeprint', function () {
    beforePrint = root.getAttribute('data-theme');
    root.setAttribute('data-theme', 'light');
    all('details').forEach(function (d) {
      d.open = true;
    });
  });
  window.addEventListener('afterprint', function () {
    if (beforePrint === null) {
      root.removeAttribute('data-theme');
    } else {
      root.setAttribute('data-theme', beforePrint);
    }
  });

  root.classList.add('js');

  // Results filter: only the reports that list requirements carry it.
  var box = document.getElementById('filter-text');
  if (box === null) {
    return;
  }
  var reqs = all('article.requirement');
  var groups = all('#results details.group');
  var shown = document.getElementById('filter-count');
  var buttons = all('button.filter');
  var status = 'all';

  // Each requirement is an article holding one disclosure, so opening and
  // closing it reaches past the article to that element.
  function panel(req) {
    return req.querySelector('details');
  }

  function matches(d, query) {
    if (status !== 'all') {
      if (d.getAttribute('data-status') !== status) {
        return false;
      }
    }
    if (query === '') {
      return true;
    }
    return d.querySelector('summary').textContent.toLowerCase().indexOf(query) !== -1;
  }

  function apply() {
    var query = box.value.trim().toLowerCase();
    var filtering = query !== '' || status !== 'all';
    var visible = 0;
    reqs.forEach(function (d) {
      var ok = matches(d, query);
      d.hidden = !ok;
      if (ok) {
        visible += 1;
      }
    });
    // A filter is no use if its matches sit inside closed groups.
    groups.forEach(function (g) {
      var any = g.querySelector('article.requirement:not([hidden])') !== null;
      g.hidden = filtering ? !any : false;
      if (filtering) {
        g.open = any;
      }
    });
    shown.textContent = visible + ' of ' + reqs.length + ' requirements shown';
  }

  function setOpen(open) {
    groups.forEach(function (g) {
      if (!g.hidden) {
        g.open = open;
      }
    });
    reqs.forEach(function (d) {
      if (!d.hidden) {
        panel(d).open = open;
      }
    });
  }

  buttons.forEach(function (b) {
    b.addEventListener('click', function () {
      status = b.getAttribute('data-status');
      buttons.forEach(function (other) {
        other.setAttribute('aria-pressed', other === b ? 'true' : 'false');
      });
      apply();
    });
  });
  box.addEventListener('input', apply);
  document.getElementById('expand-all').addEventListener('click', function () {
    setOpen(true);
  });
  document.getElementById('collapse-all').addEventListener('click', function () {
    setOpen(false);
  });
  apply();
})();
