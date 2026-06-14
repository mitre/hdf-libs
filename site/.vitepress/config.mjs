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

const VERSIONS = loadVersionsManifest();

// Sidebar config — one entry per URL prefix. The empty-prefix entry
// (`/schemas/`) serves the current version. Each historical version
// gets its own (`/v3.X.Y/schemas/`).
function buildSidebar() {
  const sidebar = {
    '/': [
      {
        text: 'Guide',
        items: [
          { text: 'Overview', link: '/' },
          { text: 'Schema Reference', link: '/schemas/' },
        ],
      },
    ],
    '/schemas/': [
      {
        text: `Document Types (${VERSIONS.current})`,
        items: getSchemaNavItems(path.resolve(__dirname, '../schemas'), ''),
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

// Nav: Schemas link plus a version dropdown on the right (last item
// before the social GitHub icon). The dropdown shows every released
// version; selecting one switches the URL prefix.
function buildNav() {
  return [
    { text: 'Schemas', link: '/schemas/' },
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
