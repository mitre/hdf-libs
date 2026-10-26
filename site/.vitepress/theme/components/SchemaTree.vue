<script setup>
import { computed, ref, watch } from 'vue';

const props = defineProps({
  value: { required: true },
  name: { type: String, default: '' },
  depth: { type: Number, default: 0 },
  expansion: { type: Object, default: null },
});
const open = ref(props.expansion?.open ?? (props.depth === 0));
watch(() => props.expansion, (command) => {
  if (command) open.value = command.open;
});
const container = computed(() => props.value !== null && typeof props.value === 'object');
const entries = computed(() => container.value ? Object.entries(props.value) : []);
const label = computed(() => props.depth > 0 ? `${JSON.stringify(props.name)}: ` : '');
</script>

<template>
  <details v-if="container" class="schema-tree" :open="open" @toggle="open = $event.target.open">
    <summary>
      <span class="schema-tree-key">{{ label }}</span>
      <span class="schema-tree-count">{{ Array.isArray(value) ? '[' : '{' }} {{ entries.length }} {{ Array.isArray(value) ? 'items ]' : 'properties }' }}</span>
    </summary>
    <div v-if="open" class="schema-tree-children">
      <SchemaTree v-for="[key, child] in entries" :key="key" :name="key" :value="child" :depth="depth + 1" :expansion="expansion" />
    </div>
  </details>
  <div v-else class="schema-tree-leaf">
    <span class="schema-tree-key">{{ label }}</span><span :class="`schema-tree-${typeof value}`">{{ JSON.stringify(value) }}</span>
  </div>
</template>
