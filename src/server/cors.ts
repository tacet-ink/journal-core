/**
 * cors.ts — 共用 CORS 本體（多產品 diff 證實完全一致，直取）。
 */
export const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  // preflight 快取（卡C t_7361b68c：缺 Max-Age＝瀏覽器對每個跨域請求重跑 OPTIONS preflight；
  // 24h 落在業界 600-86400 慣例區間。Workers 對 OPTIONS 一律走 handleOptions 放行，
  // 快取命中不影響伺服器語意）。
  'Access-Control-Max-Age': '86400',
};

export function corsResponse(res: Response): Response {
  const newHeaders = new Headers(res.headers);
  Object.entries(CORS_HEADERS).forEach(([k, v]) => newHeaders.set(k, v));
  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers: newHeaders,
  });
}