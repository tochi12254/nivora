import React, { useEffect } from 'react'
import { useGetNetworkStatsQuery } from '../features/api/cyberwatchApi'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts'

const NetworkStats = () => {
  const { data: stats, isFetching } = useGetNetworkStatsQuery(undefined, {
    pollingInterval: 5000
  })

  const formatData = (stats) => {
    if (!stats) return []
    return [
      { name: 'Active Connections', value: stats.active_connections },
      { name: 'Known Hosts', value: stats.known_hosts },
      { name: 'Threats Detected', value: stats.threats_detected }
    ]
  }

  return (
    <div className="network-stats">
      <h2>Network Statistics</h2>
      {isFetching && <div>Updating data...</div>}
      <LineChart width={600} height={300} data={formatData(stats)}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="name" />
        <YAxis />
        <Tooltip />
        <Legend />
        <Line type="monotone" dataKey="value" stroke="#8884d8" />
      </LineChart>
    </div>
  )
}

export default NetworkStats