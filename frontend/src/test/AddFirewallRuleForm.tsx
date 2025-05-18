import React, { useState } from 'react'
import { useAddFirewallRuleMutation } from '../features/firewall/firewallApi'
import { FirewallRuleAction, FirewallRuleDirection, FirewallRuleProtocol } from '../features/firewall/firewallTypes'

const AddFirewallRuleForm: React.FC = () => {
  const [addRule] = useAddFirewallRuleMutation()
  const [formData, setFormData] = useState({
    action: 'deny' as FirewallRuleAction,
    direction: 'in' as FirewallRuleDirection,
    source_ip: '',
    destination_ip: '',
    protocol: 'any' as FirewallRuleProtocol,
    source_port: '',
    destination_port: '',
    interface: '',
    description: ''
  })

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await addRule({
        ...formData,
        source_port: formData.source_port ? parseInt(formData.source_port) : undefined,
        destination_port: formData.destination_port ? parseInt(formData.destination_port) : undefined
      }).unwrap()
      // Reset form or show success message
    } catch (error) {
      // Handle error
    }
  }

  return (
    <form onSubmit={handleSubmit} className="firewall-rule-form">
      <div className="form-group">
        <label>Action</label>
        <select 
          value={formData.action}
          onChange={(e) => setFormData({...formData, action: e.target.value as FirewallRuleAction})}
        >
          <option value="allow">ALLOW</option>
          <option value="deny">DENY</option>
        </select>
      </div>

      <div className="form-group">
        <label>Direction</label>
        <select 
          value={formData.direction}
          onChange={(e) => setFormData({...formData, direction: e.target.value as FirewallRuleDirection})}
        >
          <option value="in">INBOUND</option>
          <option value="out">OUTBOUND</option>
          <option value="any">ANY</option>
        </select>
      </div>

      <div className="form-group">
        <label>Protocol</label>
        <select 
          value={formData.protocol}
          onChange={(e) => setFormData({...formData, protocol: e.target.value as FirewallRuleProtocol})}
        >
          <option value="any">ANY</option>
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
          <option value="icmp">ICMP</option>
        </select>
      </div>

      <div className="form-group">
        <label>Source IP</label>
        <input 
          type="text" 
          placeholder="0.0.0.0/0" 
          value={formData.source_ip}
          onChange={(e) => setFormData({...formData, source_ip: e.target.value})}
        />
      </div>

      <div className="form-group">
        <label>Destination IP</label>
        <input 
          type="text" 
          placeholder="0.0.0.0/0" 
          value={formData.destination_ip}
          onChange={(e) => setFormData({...formData, destination_ip: e.target.value})}
        />
      </div>

      <div className="form-row">
        <div className="form-group">
          <label>Source Port</label>
          <input 
            type="number" 
            placeholder="Any" 
            min="1" 
            max="65535"
            value={formData.source_port}
            onChange={(e) => setFormData({...formData, source_port: e.target.value})}
          />
        </div>

        <div className="form-group">
          <label>Destination Port</label>
          <input 
            type="number" 
            placeholder="Any" 
            min="1" 
            max="65535"
            value={formData.destination_port}
            onChange={(e) => setFormData({...formData, destination_port: e.target.value})}
          />
        </div>
      </div>

      <div className="form-group">
        <label>Interface (Optional)</label>
        <input 
          type="text" 
          placeholder="eth0" 
          value={formData.interface}
          onChange={(e) => setFormData({...formData, interface: e.target.value})}
        />
      </div>

      <div className="form-group">
        <label>Description (Optional)</label>
        <input 
          type="text" 
          placeholder="Rule description" 
          value={formData.description}
          onChange={(e) => setFormData({...formData, description: e.target.value})}
        />
      </div>

      <button type="submit" className="submit-button">
        Add Firewall Rule
      </button>
    </form>
  )
}

export default AddFirewallRuleForm