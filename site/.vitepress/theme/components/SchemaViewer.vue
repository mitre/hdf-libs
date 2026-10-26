<script setup>
import { computed, onMounted, onUnmounted, ref, shallowRef, useId, watch } from 'vue';
import { withBase } from 'vitepress';
import { VPButton } from 'vitepress/theme';
import { schemaSections } from '../schema-viewer.mjs';
import SchemaTree from './SchemaTree.vue';

const props = defineProps({ src: { type: String, required: true } });
const sectionId = useId();
const schema = shallowRef(null);
const selected = ref(0);
const expansion = shallowRef(null);
const loading = ref(true);
const error = ref('');
const sections = computed(() => schema.value ? schemaSections(schema.value) : []);
let request;

async function load(src) {
  request?.abort();
  const current = new AbortController();
  request = current;
  schema.value = null;
  expansion.value = null;
  selected.value = 0;
  loading.value = true;
  error.value = '';
  try {
    const response = await fetch(withBase(src), { signal: current.signal });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Expected a schema object');
    if (!current.signal.aborted) schema.value = data;
  } catch (cause) {
    if (!current.signal.aborted) error.value = `Unable to load the interactive schema (${cause.message}).`;
  } finally {
    if (!current.signal.aborted) loading.value = false;
  }
}

onMounted(() => watch(() => props.src, load, { immediate: true }));
onUnmounted(() => request?.abort());
watch(selected, () => { expansion.value = null; });
</script>

<template>
  <section class="schema-viewer" aria-label="Interactive schema">
    <p class="schema-viewer-intro">Expand a field to explore its structure, or choose a definition.</p>
    <p v-if="loading" role="status">Loading interactive schema…</p>
    <p v-else-if="error" role="alert">{{ error }} <a :href="withBase(src)">Download the schema</a> or use the reference tables below.</p>
    <template v-else>
      <div class="schema-viewer-selector">
        <label :for="sectionId">Schema section</label>
        <select :id="sectionId" v-model="selected">
          <option v-for="(section, index) in sections" :key="index" :value="index">{{ section.label }}</option>
        </select>
      </div>
      <div class="schema-viewer-actions" role="group" aria-label="Schema expansion">
        <VPButton theme="alt" text="Expand all" type="button" @click="expansion = { open: true }" />
        <VPButton theme="alt" text="Collapse all" type="button" @click="expansion = { open: false }" />
      </div>
      <div class="schema-viewer-tree" tabindex="0" aria-label="Schema JSON">
        <SchemaTree :key="`${src}:${selected}`" :value="sections[selected].value" :expansion="expansion" />
      </div>
    </template>
  </section>
</template>
