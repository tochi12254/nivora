import React from 'react'
import { useGetThreatsQuery } from '../features/api/cyberwatchApi'

const ThreatList = () => {
  const { data: threats, isLoading, isError } = useGetThreatsQuery()

  if (isLoading) return <div>Loading threats...</div>
  if (isError) return <div>Error loading threats</div>

  return (
    <div className="threat-list">
      <h2>Detected Threats</h2>
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Type</th>
            <th>Source IP</th>
            <th>Destination IP</th>
            <th>Protocol</th>
          </tr>
        </thead>
        <tbody>
          {threats?.map(threat => (
            <tr key={threat.id}>
              <td>{new Date(threat.timestamp).toLocaleString()}</td>
              <td>{threat.threat_type}</td>
              <td>{threat.source_ip}</td>
              <td>{threat.destination_ip}</td>
              <td>{threat.protocol}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default ThreatList