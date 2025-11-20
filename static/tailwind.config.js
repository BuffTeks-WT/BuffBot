module.exports = {
  content: ["./templates/**/*.html", "./static/js/**/*.js"],
  theme: {
    extend: {
      fontFamily: {
        display: ['"Bebas Neue"', "Inter", "system-ui", "sans-serif"],
        sans: ["Inter", "system-ui", "sans-serif"],
	archivo: ['Archivo', 'sans-serif'],      
      },
	backgroundImage: {
      'bh-hero': 'linear-gradient(to bottom right, rgba(249,115,22,0.2), rgba(244,63,94,0.1), rgba(217,70,239,0.1))',
    },    
      colors: {
        bg: "rgb(var(--bg))",
        fg: "rgb(var(--fg))",
        accent: "rgb(var(--accent))",
        card: "rgb(var(--card))",
        border: "rgb(var(--border))",
      },
      boxShadow: {
        glass: "0 8px 30px rgba(0,0,0,.18), inset 0 1px rgba(255,255,255,.06)",
      },
      borderRadius: { xl: "1rem", "2xl": "1.25rem" },
    },
  },
  plugins: [],
};

