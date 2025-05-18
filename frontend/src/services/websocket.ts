import { store } from '../app/store'
import { threatDetected, packetReceived } from '../features/network/networkSlice'

class CyberWatchWebSocket {
  private socket: WebSocket | null = null
  private reconnectAttempts = 0
  private maxReconnectAttempts = 5

  connect() {
    this.socket = new WebSocket(`ws://${window.location.host}/ws/alerts?token=${localStorage.getItem('token')}`)

    this.socket.onopen = () => {
      this.reconnectAttempts = 0
      console.log('WebSocket connected')
      this.subscribe(['threats', 'packets'])
    }

    this.socket.onmessage = (event) => {
      const data = JSON.parse(event.data)
      
      // Dispatch to Redux based on message type
      switch(data.type) {
        case 'threat':
          store.dispatch(threatDetected(data.payload))
          break
        case 'packet':
          store.dispatch(packetReceived(data.payload))
          break
        case 'firewall_action':
          // Handle firewall actions
          break
      }
    }

    this.socket.onclose = () => {
      if (this.reconnectAttempts < this.maxReconnectAttempts) {
        setTimeout(() => {
          this.reconnectAttempts++
          this.connect()
        }, 1000 * this.reconnectAttempts)
      }
    }
  }

  subscribe(channels: string[]) {
    if (this.socket?.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify({
        type: 'subscribe',
        channels
      }))
    }
  }

  disconnect() {
    this.socket?.close()
  }
}

export const cyberWatchWebSocket = new CyberWatchWebSocket()