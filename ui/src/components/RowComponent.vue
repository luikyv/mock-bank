<template>
  <div
    class="flex items-start justify-between p-4 bg-white rounded-2xl shadow hover:bg-gray-50 group relative"
  >
    <!-- Title and tags -->
    <div class="flex-1 cursor-pointer" @click="onClick()">
      <p class="font-semibold text-gray-800 group-hover:text-black">
        {{ title }}
      </p>
      <p
        v-for="tag in tags"
        :key="tag.key"
        class="text-sm text-gray-500 truncate"
      >
        {{ tag.key }}: {{ tag.value }}
      </p>
    </div>
  </div>
</template>

<script setup lang="ts">
defineProps<{
  title: string;
  onClick: (() => Promise<void>) | (() => void);
  tags?: { key: string; value: string }[];
}>();
</script>
