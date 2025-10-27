// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";

// https://astro.build/config
export default defineConfig({
  integrations: [
    starlight({
      title: "pysecfw",
      description: "Modular Python Security Framework for Penetration Testing",
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/ajutamangdev/pysecfw",
        },
      ],
      sidebar: [
        {
          label: "Introduction",
          items: [
            { label: "Overview", slug: "introduction/overview" },
            { label: "Installation", slug: "introduction/installation" },
            { label: "Quick Start", slug: "introduction/quick-start" },
          ],
        },
        {
          label: "Guides",
          items: [
            { label: "Usage Guide", slug: "guides/usage" },
            { label: "AWS", slug: "guides/aws" },
            { label: "Contribution", slug: "guides/contribution" },
          ],
        },
      ],
      customCss: [
        // Optional: Add custom CSS if needed
      ],
      editLink: {
        baseUrl: "https://github.com/ajutamangdev/pysecfw/edit/docs/docs/",
      },
    }),
  ],
});
