module.exports = {
  apps: [
    {
      name: 'argus',
      script: 'src/app.js',
      instances: 1,
      exec_mode: 'fork',
      watch: false,
      env: {
        NODE_ENV: 'production',
        PORT: 3000,
        DB_FILE: './data/argus.db',
        RETENTION_DAYS: 1095,
        NORMAL_INTERVAL_MS: 60000,
        DOWN_INTERVAL_MS: 15000,
        CONFIRMATION_RETRIES: 3,
        CONFIRMATION_RETRY_INTERVAL_MS: 5000,
        DEFAULT_TIMEOUT_MS: 10000,
        WEBHOOK_DISPLAY_NAME: 'Argus',
        WEBHOOK_PUBLIC_BASE_URL: 'https://monitor.example.com',
        WEBHOOK_ICON_PATH: '/img/argus.jpg'
      }
    }
  ]
};
