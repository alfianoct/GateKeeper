import { API } from './config.js';

let onUnauth = () => {};
let onApiError = () => {};

export function setOnUnauth(fn) {
    onUnauth = fn;
}

export function setOnApiError(fn) {
    onApiError = fn;
}

async function api(method, path, body) {
    try {
        const opts = {
            method,
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
        };
        if (body) opts.body = JSON.stringify(body);
        const res = await fetch(API + path, opts);
        if (res.status === 401) {
            onUnauth();
            throw new Error('session expired');
        }
        if (res.status === 204) return null;
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
        return data;
    } catch (e) {
        if (e.message === 'session expired') throw e;
        if (typeof onApiError === 'function') onApiError(e);
        throw e;
    }
}

export const get = (path) => api('GET', path);
export const post = (path, body) => api('POST', path, body);
export const put = (path, body) => api('PUT', path, body);
export const del = (path) => api('DELETE', path);
