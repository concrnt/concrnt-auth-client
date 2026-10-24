import { createAuthClient } from 'better-auth/react'
import { concrntClient } from '@concrnt/better-auth/client'

// baseURL は同一オリジンの /api/auth (既定) なので指定不要
export const authClient = createAuthClient({ plugins: [concrntClient()] })
