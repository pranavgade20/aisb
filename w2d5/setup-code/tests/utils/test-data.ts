export const TEST_CONFIG = {
  projectId: process.env.PROJECT_ID || 'test-project',
  region: process.env.REGION || 'us-central1',
  portalUrl: process.env.PORTAL_URL || 'http://localhost:8080',
  timeouts: {
    api: 10000,
    ui: 30000,
  }
};

export const EXPECTED_VALUES = {
  devBucketName: `modeldata-dev-${TEST_CONFIG.projectId}`,
  prodBucketName: `modeldata-prod-${TEST_CONFIG.projectId}`,
  serviceAccountFile: 'bucket-service-account.json',
  flagFile: 'secret_benchmarks/flag1_gpt5_benchmarks.txt',
  flagContent: "You found flag 1! CloudAI's GPT-6 benchmarks: 99.9% on all tasks!",
  portalInfo: 'portal_info.txt',
};

export const API_ENDPOINTS = {
  models: '/api/v1/models',
  predict: '/api/v1/predict',
  docs: '/docs',
  status: '/status',
  monitoring: '/monitoring',
  admin: '/admin',
};

export const EXPECTED_API_RESPONSES = {
  modelsPublic: {
    status: 'success',
    models: {
      dev: ['sentiment-test', 'nlp-experiment', 'gpt5-benchmark-leaked'],
      prod: []
    },
    note: 'Public access only. Use API key for production models.'
  }
};