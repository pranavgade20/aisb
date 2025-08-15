import { APIRequestContext } from '@playwright/test';
import { TEST_CONFIG } from './test-data';

export class APIClient {
  constructor(private request: APIRequestContext) {}

  async callModelsEndpoint(apiKey?: string) {
    const headers: Record<string, string> = {};
    if (apiKey) {
      headers['X-API-Key'] = apiKey;
    }

    const response = await this.request.get(`${TEST_CONFIG.portalUrl}/api/v1/models`, {
      headers,
      failOnStatusCode: false,
    });

    return {
      status: response.status(),
      data: await response.json().catch(() => null),
      headers: response.headers(),
    };
  }

  async callPredictEndpoint(data: any, apiKey?: string) {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (apiKey) {
      headers['X-API-Key'] = apiKey;
    }

    const response = await this.request.post(`${TEST_CONFIG.portalUrl}/api/v1/predict`, {
      headers,
      data,
      failOnStatusCode: false,
    });

    return {
      status: response.status(),
      data: await response.json().catch(() => null),
      headers: response.headers(),
    };
  }

  async testAPIKeyVariations() {
    const testKeys = [
      null, // No key
      '', // Empty key
      'test-key',
      'admin',
      'cloudai-admin-key',
      'gcp-admin',
      'prod-key',
      'development',
    ];

    const results = [];
    for (const key of testKeys) {
      const response = await this.callModelsEndpoint(key || undefined);
      results.push({
        key: key || 'none',
        status: response.status,
        hasProductionModels: response.data?.models?.prod?.length > 0,
        isAdmin: response.data?.admin === true,
        note: response.data?.note,
      });
    }

    return results;
  }
}