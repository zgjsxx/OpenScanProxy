export async function getJson(url) {
  const resp = await fetch(url, { credentials: 'include' })
  if (resp.status === 401) throw new Error('UNAUTHORIZED')
  if (!resp.ok) throw new Error(`HTTP_${resp.status}`)
  return resp.json()
}

export async function postJson(url, payload = {}) {
  const resp = await fetch(url, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (resp.status === 401) throw new Error('UNAUTHORIZED')
  if (!resp.ok) throw new Error(`HTTP_${resp.status}`)
  return resp.json()
}
