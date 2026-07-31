import type { Config } from 'tailwindcss';

export default {
  content: ['./src/**/*.{js,ts,jsx,tsx,mdx}'],
  theme: {
    extend: {
      colors: {
        voting: {
          surface: '#091422',
          'surface-lowest': '#050e1d',
          'surface-low': '#121c2a',
          container: '#16202f',
          'container-high': '#202a3a',
          'container-highest': '#2b3545',
          primary: '#cebdff',
          'primary-container': '#a78bfa',
          'on-primary': '#381385',
          secondary: '#b9c6e8',
          tertiary: '#d0bcff',
          text: '#d9e3f7',
          muted: '#cac4d4',
          error: '#ffb4ab',
        },
      },
      borderRadius: {
        DEFAULT: '0.5rem',
        md: '0.75rem',
        lg: '1rem',
        xl: '1.5rem',
      },
      fontFamily: {
        sans: ['var(--font-hanken-grotesk)', 'ui-sans-serif', 'system-ui'],
        mono: ['var(--font-jetbrains-mono)', 'ui-monospace', 'monospace'],
      },
    },
  },
  plugins: [],
} satisfies Config;
