const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1'
export type ApiError = { detail?: string }
export async function api<T>(path: string, token: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...(options.headers || {}) },
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({})) as ApiError
    throw new Error(body.detail || `Falha na API (${response.status})`)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}
export async function login(email: string, password: string) {
  const form = new URLSearchParams({ username: email, password })
  const response = await fetch(`${API_BASE}/auth/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form })
  if (!response.ok) throw new Error('E-mail ou senha incorretos')
  return response.json() as Promise<{ access_token: string; user: { email: string; role: string } }>
}
