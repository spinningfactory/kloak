import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Kloak',
  description: 'Kubernetes eBPF Secret Interceptor — Documentation',
  base: '/docs/',
  appearance: 'dark',

  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/transparent-logo.svg' }],
  ],

  themeConfig: {
    logo: '/transparent-logo.svg',
    siteTitle: 'Kloak Docs',

    nav: [
      { text: 'Getting Started', link: '/getting-started/quick-start' },
      { text: 'Guides', link: '/guides/protecting-secrets' },
      { text: 'Tutorials', link: '/tutorials/openclaw-with-kloak' },
      { text: 'Architecture', link: '/architecture/overview' },
      { text: 'Reference', link: '/reference/labels-annotations' },
    ],

    sidebar: [
      {
        text: 'Getting Started',
        items: [
          { text: 'Quick Start', link: '/getting-started/quick-start' },
          { text: 'Installation', link: '/getting-started/installation' },
          { text: 'Configuration', link: '/getting-started/configuration' },
        ],
      },
      {
        text: 'Guides',
        items: [
          { text: 'Protecting Secrets', link: '/guides/protecting-secrets' },
          { text: 'Host Filtering', link: '/guides/host-filtering' },
          { text: 'Supported Runtimes', link: '/guides/supported-runtimes' },
        ],
      },
      {
        text: 'Tutorials',
        items: [
          { text: 'OpenClaw with Kloak', link: '/tutorials/openclaw-with-kloak' },
        ],
      },
      {
        text: 'Architecture',
        items: [
          { text: 'Overview', link: '/architecture/overview' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'Labels & Annotations', link: '/reference/labels-annotations' },
          { text: 'Requirements', link: '/reference/requirements' },
        ],
      },
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/getkloak/kloak' },
    ],

    editLink: {
      pattern: 'https://github.com/getkloak/kloak/edit/main/website/docs/:path',
      text: 'Edit this page on GitHub',
    },

    footer: {
      message: 'Released under the Apache 2.0 License.',
      copyright: 'Copyright 2025-present Kloak Contributors',
    },

    search: {
      provider: 'local',
    },
  },
})
