import { defineConfig } from 'vitepress';
import fs from 'fs';
import path from 'path';

// Load the version manifest produced by generate-schema-docs.mjs. The
// manifest lists every version with a rendered docs tree on disk; the
// nav dropdown and per-version sidebar config are derived from it.
function loadVersionsManifest() {
  const file = path.resolve(__dirname, 'versions.json');
  if (!fs.existsSync(file)) {
    // First-run fallback: only the current build exists.
    return { current: 'v3.3.0', versions: ['v3.3.0'] };
  }
  return JSON.parse(fs.readFileSync(file, 'utf-8'));
}

// Discover the schema pages present under a given directory and return
// a sidebar items array. Used both for the current /schemas/ tree and
// for each /v<X.Y.Z>/schemas/ tree.
function getSchemaNavItems(schemasDir, urlPrefix) {
  if (!fs.existsSync(schemasDir)) return [];
  return fs.readdirSync(schemasDir)
    .filter((f) => f.endsWith('.md') && f !== 'index.md')
    .sort()
    .map((f) => {
      const name = f.replace('.md', '');
      const content = fs.readFileSync(path.join(schemasDir, f), 'utf-8');
      const match = content.match(/^#\s+(.+)/m);
      const text = (match ? match[1] : name).replace(/ — v\d+\.\d+\.\d+$/, '');
      return { text, link: `${urlPrefix}/schemas/${name}` };
    });
}

// Discover markdown pages in a docs subdirectory (specification, guides,
// architecture, contributing). Each page's display name is its first
// heading; the sidebar link is the path-without-extension.
function getDocsItems(subdir) {
  const dir = path.resolve(__dirname, `../docs/${subdir}`);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter((f) => f.endsWith('.md') && f !== 'index.md')
    .sort()
    .map((f) => {
      const name = f.replace('.md', '');
      const content = fs.readFileSync(path.join(dir, f), 'utf-8');
      const match = content.match(/^#\s+(.+)/m);
      const text = match ? match[1] : name;
      return { text, link: `/docs/${subdir}/${name}` };
    });
}

const VERSIONS = loadVersionsManifest();

// Sidebar config — one entry per URL prefix. The empty-prefix entry
// (`/schemas/`) serves the current version. Each historical version
// gets its own (`/v3.X.Y/schemas/`). The `/docs/` tree gets its own
// sidebar grouped by subdirectory.
function buildSidebar() {
  const sidebar = {
    '/': [
      {
        text: 'Resources',
        items: [
          { text: 'Overview', link: '/' },
          { text: 'Schema Reference', link: '/schemas/' },
          { text: 'Documentation', link: '/docs/' },
        ],
      },
    ],
    '/schemas/': [
      {
        text: `Document Types (${VERSIONS.current})`,
        items: getSchemaNavItems(path.resolve(__dirname, '../schemas'), ''),
      },
    ],
    '/docs/': [
      {
        text: 'Start here',
        items: [
          { text: 'Documentation home', link: '/docs/' },
          { text: 'HDF Readers\' Guide', link: '/docs/architecture/hdf-readers-guide' },
        ],
      },
      {
        text: 'Specification',
        items: getDocsItems('specification'),
      },
      {
        text: 'Architecture',
        items: getDocsItems('architecture'),
      },
      {
        text: 'Guides',
        items: getDocsItems('guides'),
      },
      {
        text: 'Contributing',
        items: getDocsItems('contributing'),
      },
    ],
  };

  for (const v of VERSIONS.versions) {
    if (v === VERSIONS.current) continue;
    const schemasDir = path.resolve(__dirname, `../${v}/schemas`);
    sidebar[`/${v}/schemas/`] = [
      {
        text: `Document Types (${v})`,
        items: getSchemaNavItems(schemasDir, `/${v}`),
      },
    ];
  }

  return sidebar;
}

// Nav: Schemas + Documentation + version dropdown (last item before the
// social GitHub icon). The dropdown shows every released schema version;
// selecting one switches the schema-page URL prefix. The Documentation
// link points at the docs landing (specification, guides, architecture).
function buildNav() {
  return [
    { text: 'Schemas', link: '/schemas/' },
    { text: 'Documentation', link: '/docs/' },
    {
      text: VERSIONS.current,
      items: VERSIONS.versions.map((v) => ({
        text: v === VERSIONS.current ? `${v} (latest)` : v,
        link: v === VERSIONS.current ? '/schemas/' : `/${v}/schemas/`,
      })),
    },
  ];
}

export default defineConfig({
  title: 'HDF Schemas',
  description: 'Heimdall Data Format (HDF) JSON Schema Reference',
  base: '/hdf-libs/',

  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/hdf-libs/saf-logo.svg' }],
    ['script', { async: '', src: 'https://www.googletagmanager.com/gtag/js?id=G-MN92QDWHGV' }],
    ['script', {}, `window.dataLayer = window.dataLayer || [];
function gtag(){dataLayer.push(arguments);}
gtag('js', new Date());
gtag('config', 'G-MN92QDWHGV');`],
  ],

  themeConfig: {
    logo: '/saf-logo.svg',
    nav: buildNav(),
    sidebar: buildSidebar(),

    socialLinks: [
      { icon: 'github', link: 'https://github.com/mitre/hdf-libs' },
    ],

    footer: {
      message: 'Released under the Apache 2.0 License.',
      copyright: `Copyright © ${new Date().getFullYear()} MITRE Corporation`,
    },

    search: {
      provider: 'local',
    },
  },
});
