import { definePluginEntry } from 'openclaw/plugin-sdk/plugin-entry';
import { PLUGIN_ID, register } from './guard.ts';

export default definePluginEntry({
  id: PLUGIN_ID,
  name: 'PII Guard',
  description: 'Blocks known personal-data formats in text an agent sends to another agent.',
  register,
});
