export function schemaSections(schema) {
  const sections = [{ label: 'Full schema', value: schema }];
  if (schema.properties) sections.push({ label: 'Properties', value: schema.properties });
  const definitions = schema.$defs || schema.definitions || {};
  for (const [name, value] of Object.entries(definitions)) {
    const label = value?.title || name;
    sections.push({ label, value });
    for (const [child, definition] of Object.entries(value?.$defs || value?.definitions || {})) {
      sections.push({ label: `${label} / ${child}`, value: definition });
    }
  }
  return sections;
}
