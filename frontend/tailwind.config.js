/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx}"
  ],
  theme: {
    extend: {
      colors: {
        'kurz-dark': '#080f2b',
        'kurz-blue': '#0044cc',
        'kurz-cyan': '#01b6fe',
        'kurz-purple': '#3b0297',
        'kurz-pink': '#cb01b3',
        'kurz-orange': '#fe5a01',
        'kurz-green': '#00cc88',
        'kurz-yellow': '#fed401',
        'kurz-bg': '#f4f5f7'
      },
      fontFamily: {
        'display': ['Montserrat', 'sans-serif'],
        'body': ['Outfit', 'sans-serif'],
        'mono': ['Space Mono', 'monospace']
      },
      borderWidth: {
        '2': '2px'
      }
    }
  },
  plugins: []
}
