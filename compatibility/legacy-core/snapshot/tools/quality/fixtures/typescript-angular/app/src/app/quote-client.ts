import { OpenAPI, DefaultService } from './generated';

export async function fetchQuote(baseUrl: string) {
  OpenAPI.BASE = baseUrl;
  return DefaultService.getQuote();
}
