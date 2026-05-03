<template>
  <div class="search-select" ref="rootEl">
    <div class="search-select-chips" v-if="selectedItems.length">
      <span v-for="item in selectedItems" :key="item.value" class="search-chip" :class="{ group: item.isGroup }">
        {{ item.label }}
        <button class="search-chip-del" @click="removeItem(item)">&times;</button>
      </span>
    </div>
    <input
      v-model="query"
      class="search-select-input"
      :placeholder="placeholder"
      @focus="open = true"
      @keydown.escape="open = false"
      @keydown.enter.prevent="selectHighlighted"
      @keydown.arrow-down.prevent="highlightNext"
      @keydown.arrow-up.prevent="highlightPrev"
    />
    <div class="search-dropdown" v-if="open && filteredItems.length">
      <template v-if="filteredGroups.length">
        <div class="search-dropdown-section">用户组</div>
        <div
          v-for="(item, idx) in filteredGroups"
          :key="item.value"
          class="search-dropdown-item"
          :class="{ highlighted: highlightIndex === idx }"
          @mousedown.prevent="selectItem(item)"
        >
          <span class="search-dropdown-label">{{ item.label }}</span>
          <span class="search-dropdown-hint">{{ item.memberCount }} 人</span>
        </div>
      </template>
      <template v-if="filteredUsers.length">
        <div class="search-dropdown-section">用户</div>
        <div
          v-for="item in filteredUsers"
          :key="item.value"
          class="search-dropdown-item"
          :class="{ highlighted: highlightIndex === filteredGroups.length + getFilteredUserIndex(item.value) }"
          @mousedown.prevent="selectItem(item)"
        >
          <span class="search-dropdown-label">{{ item.label }}</span>
        </div>
      </template>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onBeforeUnmount, ref, nextTick } from 'vue'

const props = defineProps({
  modelValue: { type: String, default: '' },
  users: { type: Array, default: () => [] },
  groups: { type: Array, default: () => [] },
  placeholder: { type: String, default: '搜索用户或用户组...' },
})

const emit = defineEmits(['update:modelValue'])

const query = ref('')
const open = ref(false)
const highlightIndex = ref(0)
const rootEl = ref(null)

const selectedItems = computed(() => {
  const items = []
  const seen = new Set()
  if (props.modelValue) {
    for (const line of props.modelValue.split('\n')) {
      const v = line.trim()
      if (!v || seen.has(v)) continue
      seen.add(v)
      const isGroup = v.startsWith('@')
      items.push({
        value: isGroup ? v.slice(1) : v,
        label: v,
        isGroup,
      })
    }
  }
  return items
})

const selectedValues = computed(() => new Set(selectedItems.value.map(i => i.value)))

const availableGroups = computed(() => {
  return (props.groups || [])
    .map(g => ({ value: g.name, label: '@' + g.name, isGroup: true, memberCount: (g.users || []).length }))
    .filter(g => !selectedValues.value.has(g.value))
})

const availableUsers = computed(() => {
  return (props.users || [])
    .map(u => ({ value: u.username, label: u.username, isGroup: false }))
    .filter(u => !selectedValues.value.has(u.value))
})

const filteredGroups = computed(() => {
  const q = query.value.trim().toLowerCase()
  if (!q) return availableGroups.value
  return availableGroups.value.filter(g => g.value.toLowerCase().includes(q) || g.label.toLowerCase().includes(q))
})

const filteredUsers = computed(() => {
  const q = query.value.trim().toLowerCase()
  if (!q) return availableUsers.value
  return availableUsers.value.filter(u => u.value.toLowerCase().includes(q))
})

const filteredItems = computed(() => [...filteredGroups.value, ...filteredUsers.value])

function getFilteredUserIndex(userValue) {
  return filteredUsers.value.findIndex(u => u.value === userValue)
}

function totalHighlightCount() {
  return filteredGroups.value.length + filteredUsers.value.length
}

function emitValue() {
  emit('update:modelValue', selectedItems.value.map(i => i.label).join('\n'))
}

function selectItem(item) {
  const newVal = props.modelValue ? props.modelValue + '\n' + item.label : item.label
  emit('update:modelValue', newVal)
  query.value = ''
  highlightIndex.value = 0
  // Keep dropdown open for multi-select convenience
}

function removeItem(item) {
  const items = selectedItems.value.filter(i => i.value !== item.value || i.isGroup !== item.isGroup)
  emit('update:modelValue', items.map(i => i.label).join('\n'))
}

function highlightNext() {
  const total = totalHighlightCount()
  if (total === 0) return
  highlightIndex.value = (highlightIndex.value + 1) % total
}

function highlightPrev() {
  const total = totalHighlightCount()
  if (total === 0) return
  highlightIndex.value = (highlightIndex.value - 1 + total) % total
}

function selectHighlighted() {
  const item = filteredItems.value[highlightIndex.value]
  if (item) selectItem(item)
}

function onClickOutside(e) {
  if (rootEl.value && !rootEl.value.contains(e.target)) {
    open.value = false
  }
}

onMounted(() => document.addEventListener('click', onClickOutside))
onBeforeUnmount(() => document.removeEventListener('click', onClickOutside))
</script>
