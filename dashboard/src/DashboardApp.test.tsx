import { describe, expect, it } from 'vitest'
import { renderToString } from 'react-dom/server'
import { DashboardApp } from './DashboardApp'

describe('DashboardApp', () => {
  it('renders the main dashboard sections', () => {
    const html = renderToString(<DashboardApp />)
    expect(html).toContain('StealthLink Dashboard')
    expect(html).toContain('Status')
    expect(html).toContain('Tunnels')
    expect(html).toContain('Metrics')
    expect(html).toContain('Config')
  })
})
