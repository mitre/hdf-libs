/**
 * Build a $ref URL for a specific definition within a schema.
 * Reads the $id from the schema at runtime so tests don't hardcode version URLs.
 *
 * @param schema - The imported schema object (must have a $id field)
 * @param defName - The definition name (e.g., 'Base_Component')
 * @returns A $ref object for use with ajv.compile()
 */
export function schemaRef(schema: Record<string, unknown>, defName: string): { $ref: string } {
  const id = schema.$id as string;
  if (!id) throw new Error('Schema has no $id field');
  return { $ref: `${id}#/$defs/${defName}` };
}
