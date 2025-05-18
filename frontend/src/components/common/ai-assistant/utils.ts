import { Message } from './types';

// Function to get time display format
export const getTimeDisplay = (date: Date) => {
  return date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
};

// Response generation functions for different categories
export const generateThreatResponse = () => {
  const responses = [
    "The ISIMBI platform integrates multiple threat intelligence feeds including MITRE ATT&CK, OSINT sources, and proprietary threat data. Our system analyzes these feeds in real-time to identify emerging threats and correlate them with your environment.",
    "Our threat detection engine uses behavioral analysis to identify suspicious patterns across your network. The system correlates events from multiple sources to reduce false positives and prioritize critical threats.",
    "ISIMBI's threat visualization provides a global view of attack vectors and targeted industries. You can pivot from the map to detailed threat intelligence about specific actors, techniques, and indicators of compromise."
  ];
  return responses[Math.floor(Math.random() * responses.length)];
};

export const generateNetworkResponse = () => {
  const responses = [
    "The network security module provides real-time visibility into traffic patterns, connection attempts, and data flows. The interactive network map allows you to visualize your infrastructure and identify anomalies.",
    "Our network monitoring capabilities include deep packet inspection, traffic analysis, and behavioral anomaly detection. The system establishes baselines for normal traffic and alerts on deviations.",
    "ISIMBI's network security features integrate with your existing infrastructure to provide seamless monitoring. You can analyze traffic by protocol, source/destination, and apply filtering rules to focus on specific segments."
  ];
  return responses[Math.floor(Math.random() * responses.length)];
};

export const generateModelResponse = () => {
  const responses = [
    "ISIMBI leverages several AI models for security analysis. These include anomaly detection, malware classification, user behavior analysis, and log analysis models. Each model is purpose-built for specific security use cases.",
    "Our machine learning pipeline allows you to train custom security models using your own data. You can select from various algorithms including neural networks, random forests, and transformer-based models depending on your needs.",
    "The AI models in ISIMBI continuously learn and adapt based on new data. Performance metrics are tracked over time, and models can be fine-tuned or retrained to maintain high accuracy as threat landscapes evolve."
  ];
  return responses[Math.floor(Math.random() * responses.length)];
};

export const generateUserResponse = () => {
  const responses = [
    "ISIMBI's access control system is role-based, allowing you to assign users to specific roles with predefined permissions. This ensures users only have access to the features and data necessary for their responsibilities.",
    "User activity is monitored and logged to maintain accountability and detect unusual behavior. The system can alert on suspicious login attempts, privilege escalation, and unusual access patterns.",
    "The user management interface allows administrators to create, modify, and deactivate user accounts. You can also define custom roles with granular permissions to match your organization's structure."
  ];
  return responses[Math.floor(Math.random() * responses.length)];
};

export const generateSystemResponse = () => {
  const responses = [
    "ISIMBI's system settings allow you to customize the platform to your specific needs. You can configure notification preferences, report generation, and integration with other security tools.",
    "The platform supports both light and dark themes to suit your working environment. You can also configure dashboard layouts and default views for different user roles.",
    "System updates are regularly released to add new features and security improvements. The update process is designed to be minimally disruptive, with options for scheduled installations."
  ];
  return responses[Math.floor(Math.random() * responses.length)];
};

export const generateGeneralResponse = () => {
  const responses = [
    "The ISIMBI Security Platform is a comprehensive cybersecurity solution that integrates threat intelligence, network monitoring, AI-powered analytics, and user management. The platform is designed to provide real-time visibility into your security posture.",
    "ISIMBI provides a unified dashboard for security operations, bringing together data from multiple sources and presenting actionable intelligence. You can drill down into specific alerts, threats, or metrics for detailed analysis.",
    "Our platform is built around core security principles: visibility, analytics, and response. The modular architecture allows you to focus on the most relevant aspects for your organization."
  ];
  return responses[Math.floor(Math.random() * responses.length)];
};

// Function to generate AI response based on user query
export const generateAIResponse = (userQuery: string) => {
  const lowerQuery = userQuery.toLowerCase();
  let responseText = '';
  let category: Message['category'] = 'general';
  let tags: string[] = [];

  // Topic detection based on keywords
  if (lowerQuery.includes('threat') || lowerQuery.includes('attack') || lowerQuery.includes('malware')) {
    category = 'threat';
    tags = ['threat-intel', 'security'];
    responseText = generateThreatResponse();
  } else if (lowerQuery.includes('network') || lowerQuery.includes('traffic') || lowerQuery.includes('firewall')) {
    category = 'network';
    tags = ['network', 'monitoring'];
    responseText = generateNetworkResponse();
  } else if (lowerQuery.includes('model') || lowerQuery.includes('ai') || lowerQuery.includes('machine learning') || lowerQuery.includes('train')) {
    category = 'model';
    tags = ['ai', 'machine-learning'];
    responseText = generateModelResponse();
  } else if (lowerQuery.includes('user') || lowerQuery.includes('access') || lowerQuery.includes('permission') || lowerQuery.includes('role')) {
    category = 'user';
    tags = ['access-control', 'user-management'];
    responseText = generateUserResponse();
  } else if (lowerQuery.includes('system') || lowerQuery.includes('platform') || lowerQuery.includes('settings')) {
    category = 'system';
    tags = ['system', 'configuration'];
    responseText = generateSystemResponse();
  } else {
    // General information about the platform
    responseText = generateGeneralResponse();
    tags = ['general', 'help'];
  }

  return { responseText, category, tags };
};
