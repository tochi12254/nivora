import React, { useEffect, useState } from 'react';

const WebSocketNotifications = () => {
  const [message, setMessage] = useState('');

  useEffect(() => {
    const ws = new WebSocket('ws://0.0.0.0:8000/ws/events');

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        console.log("WebSocket JSON: ", data);
        setMessage(`[${data.level.toUpperCase()}] ${data.message}`);
      } catch (err) {
        console.error("Failed to parse WebSocket JSON:", err);
      }
    };

    ws.onerror = (err) => {
      console.error('WebSocket error:', err);
    };

    ws.onclose = () => {
      console.warn('WebSocket closed');
    };

    return () => ws.close();
  }, []);

  return (
    <div className="fixed bottom-4 right-4 bg-black text-green-400 p-4 rounded-lg shadow-xl font-mono">
      <h4 className="font-bold text-lg">🧠 Real-Time Intel:</h4>
      <p>{message}</p>
    </div>
  );
};

export default WebSocketNotifications;
