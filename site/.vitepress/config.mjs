import { defineConfig } from 'vitepress';
import fs from 'fs';
import path from 'path';

// Auto-discover generated schema pages for sidebar
function getSchemaNavItems() {
  const schemasDir = path.resolve(__dirname, '../schemas');
  if (!fs.existsSync(schemasDir)) return [];

  return fs.readdirSync(schemasDir)
    .filter(f => f.endsWith('.md') && f !== 'index.md')
    .sort()
    .map(f => {
      const name = f.replace('.md', '');
      // Read first heading from file for display name
      const content = fs.readFileSync(path.join(schemasDir, f), 'utf-8');
      const match = content.match(/^#\s+(.+)/m);
      const text = match ? match[1] : name;
      return { text, link: `/schemas/${name}` };
    });
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
    nav: [
      { text: 'Schemas', link: '/schemas/' },
      { text: 'Guides', link: '/docs/cve-ecosystem' },
      { text: 'GitHub', link: 'https://github.com/mitre/hdf-libs' },
    ],

    sidebar: {
      '/schemas/': [
        {
          text: 'Document Types',
          items: getSchemaNavItems(),
        },
      ],
      '/docs/': [
        {
          text: 'Guides',
          items: [
            { text: 'CVE Ecosystem', link: '/docs/cve-ecosystem' },
          ],
        },
      ],
      '/': [
        {
          text: 'Guide',
          items: [
            { text: 'Overview', link: '/' },
            { text: 'Schema Reference', link: '/schemas/' },
            { text: 'CVE Ecosystem', link: '/docs/cve-ecosystem' },
          ],
        },
      ],
    },

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
