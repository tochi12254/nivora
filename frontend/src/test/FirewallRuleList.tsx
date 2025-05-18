import React from 'react'
import { useGetFirewallRulesQuery } from '../features/firewall/firewallApi'
import { FirewallRule } from '../features/firewall/firewallTypes'

const FirewallRulesList: React.FC = () => {
  const { data: rules, isLoading, isError } = useGetFirewallRulesQuery()

  if (isLoading) return <div>Loading firewall rules...</div>
  if (isError) return <div>Error loading firewall rules</div>

  return (
    <div className="firewall-rules">
      <table>
        <thead>
          <tr>
            <th>Action</th>
            <th>Direction</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Protocol</th>
            <th>Ports</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {rules?.map((rule: FirewallRule) => (
            <tr key={rule.id} className={`rule-${rule.action}`}>
              <td>{rule.action.toUpperCase()}</td>
              <td>{rule.direction.toUpperCase()}</td>
              <td>{rule.source_ip || 'Any'}</td>
              <td>{rule.destination_ip || 'Any'}</td>
              <td>{rule.protocol?.toUpperCase() || 'Any'}</td>
              <td>
                {rule.source_port && `Src:${rule.source_port}`}
                {rule.destination_port && ` Dst:${rule.destination_port}`}
              </td>
              <td>{rule.is_active ? 'Active' : 'Inactive'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default FirewallRulesList