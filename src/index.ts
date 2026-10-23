import { definePluginEntry } from 'openclaw/plugin-sdk/plugin-entry';
import { PLUGIN_ID, register } from './guard.ts';

export default definePluginEntry({
  id: PLUGIN_ID,
  name: 'Leak Guard',
  description: 'Checks text an agent sends to another agent for secrets and personal data, by group, with a mode per group.',
  register,
});
