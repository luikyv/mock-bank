<template>
  <div class="flex justify-center mt-8" v-if="show">
    <div
      class="inline-flex rounded-md shadow-sm border border-gray-300 overflow-hidden"
      role="group"
    >
      <button
        @click="$emit('prev')"
        :disabled="!hasPrev"
        class="inline-flex items-center justify-center w-36 px-4 py-2 text-sm font-medium bg-white hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        <svg
          class="w-4 h-4 mr-2"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            d="M15 19l-7-7 7-7"
          />
        </svg>
        Previous
      </button>
      <button
        @click="$emit('next')"
        :disabled="!hasNext"
        class="inline-flex items-center justify-center w-36 px-4 py-2 text-sm font-medium bg-white hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed border-l border-gray-300"
      >
        Next
        <svg
          class="w-4 h-4 ml-2"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            d="M9 5l7 7-7 7"
          />
        </svg>
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
defineProps<{
  hasPrev: boolean;
  hasNext: boolean;
  show?: boolean;
}>();
</script>
