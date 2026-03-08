/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        background: 'var(--background)',
        foreground: 'var(--foreground)',
        card: 'var(--card)',
        'card-foreground': 'var(--card-foreground)',
        primary: 'var(--primary)',
        'primary-foreground': 'var(--primary-foreground)',
        secondary: 'var(--secondary)',
        'secondary-foreground': 'var(--secondary-foreground)',
        muted: 'var(--muted)',
        'muted-foreground': 'var(--muted-foreground)',
        accent: 'var(--accent)',
        'accent-foreground': 'var(--accent-foreground)',
        destructive: 'var(--destructive)',
        'destructive-foreground': 'var(--destructive-foreground)',
        border: 'var(--border)',
        input: 'var(--input)',
        ring: 'var(--ring)',
        success: {
          DEFAULT: 'var(--success)',
          50: 'var(--success-50)',
          100: 'var(--success-100)',
          200: 'var(--success-200)',
        },
        danger: {
          DEFAULT: 'var(--danger)',
          50: 'var(--danger-50)',
          100: 'var(--danger-100)',
          200: 'var(--danger-200)',
        },
        warning: {
          DEFAULT: 'var(--warning)',
          50: 'var(--warning-50)',
          100: 'var(--warning-100)',
          200: 'var(--warning-200)',
        },
        info: {
          DEFAULT: 'var(--info)',
          50: 'var(--info-50)',
          100: 'var(--info-100)',
          200: 'var(--info-200)',
        },
      },
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
    },
  },
  plugins: [],
}
