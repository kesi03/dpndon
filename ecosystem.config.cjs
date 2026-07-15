module.exports = {
  apps: [
    {
      name: "dpndon",
      script: "dpndon",
      args: "serve -t sse -p 8080",
      env: {
        NODE_ENV: "production",
      },
      restart_delay: 5000,
      max_restarts: 10,
      watch: false,
    },
  ],
};
