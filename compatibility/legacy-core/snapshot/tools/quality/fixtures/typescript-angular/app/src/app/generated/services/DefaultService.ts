/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { Quote } from '../models/Quote';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class DefaultService {
    /**
     * @returns Quote A quote
     * @throws ApiError
     */
    public static getQuote(): CancelablePromise<Quote> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/quote',
        });
    }
}
