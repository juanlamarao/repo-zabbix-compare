export type Baseline = {
  id: string
  name: string
  status: string
  source_version?: string
  created_at: string
  started_at?: string
  finished_at?: string
  frozen_at?: string
  totals: Record<string, number>
  error?: string
}

export type Cycle = {
  id: string
  status: string
  started_at: string
  finished_at?: string
  hosts_total: number
  hosts_processed: number
  metrics: Record<string, number>
  error?: string
}

export type Dashboard = {
  baseline: Baseline | null
  running_cycle: Cycle | null
  last_cycle: Cycle | null
  alerts: Array<{
    id: number
    severity: string
    code: string
    message: string
    object_type: string
    object_id: number
  }>
}
