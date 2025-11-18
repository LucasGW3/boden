/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./*.{php,html,js}",
    "./ui/**/*.{php,html,js}",
    "./assets/**/*.{php,html,js}",
  ],
  theme: {
    extend: {
      fontFamily: {
        // das suas configs
        sans: ['Nunito', 'ui-sans-serif', 'system-ui'],
      },
      colors: {
        brand: {
          bg: '#F9FAFB',
          surface: '#FFFFFF',
          line: '#E0E7E0',
          primary: '#5FB141',
          primaryDark: '#3C8F28',
          text: '#273418',
          muted: '#6B7280',
        },
      },
      borderRadius: {
        // do primeiro config
        lg: '0.75rem',
        xl: '1rem',
        '2xl': '1.5rem',
        // desse último snippet
        pill: '9999px',
        xl2: '1rem',
      },
      boxShadow: {
        // desse snippet novo
        soft: '0 6px 18px rgba(60,143,40,0.08)',
        // extra que você já usava antes (se não usar, pode remover)
        'soft-green':
          '0 10px 25px -5px rgba(95,177,65,.08), 0 4px 8px -1px rgba(95,177,65,.1)',
      },
    },
  },
  plugins: [],
};
