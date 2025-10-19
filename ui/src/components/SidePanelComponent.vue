<template>
  <div
    class="fixed top-0 right-0 h-screen bg-white shadow-xl border-l border-gray-200 z-50"
    :style="{ width: panelWidth + 'px' }"
  >
    <!-- Resize handle -->
    <div
      class="absolute top-0 left-0 h-full w-1 cursor-ew-resize bg-transparent z-50"
      @mousedown="startResizing"
    ></div>

    <!-- Header -->
    <div class="flex justify-between items-center p-4 border-b border-gray-200">
      <h2 class="text-lg font-semibold">{{ title }}</h2>
      <button
        @click="$emit('close')"
        class="text-gray-500 text-2xl hover:text-gray-700"
        aria-label="Close"
      >
        ×
      </button>
    </div>

    <div class="flex flex-col h-[calc(100%-64px)] overflow-hidden">
      <!-- Scrollable content -->
      <div class="flex-1 overflow-y-auto px-4 py-4 text-sm">
        <slot />
      </div>

      <div class="bg-gray-100 border-t border-gray-300 px-4 py-2">
        <slot name="panel-actions" />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onBeforeUnmount } from "vue";

defineProps<{
  title: string;
}>();

const panelWidth = ref(400);
let isResizing = false;

const startResizing = () => {
  isResizing = true;
  document.body.classList.add("no-select");
  document.addEventListener("mousemove", resizePanel);
  document.addEventListener("mouseup", stopResizing);
};

const resizePanel = (e: MouseEvent) => {
  if (isResizing) {
    const newWidth = window.innerWidth - e.clientX;
    if (newWidth >= 300 && newWidth <= 800) {
      panelWidth.value = newWidth;
    }
  }
};

const stopResizing = () => {
  isResizing = false;
  document.body.classList.remove("no-select");
  document.removeEventListener("mousemove", resizePanel);
  document.removeEventListener("mouseup", stopResizing);
};

onBeforeUnmount(() => {
  document.removeEventListener("mousemove", resizePanel);
  document.removeEventListener("mouseup", stopResizing);
});
</script>

<style scoped>
.slide-left-enter-active,
.slide-left-leave-active {
  transition:
    transform 0.3s ease,
    opacity 0.3s ease;
}
.slide-left-enter-from,
.slide-left-leave-to {
  transform: translateX(100%);
  opacity: 0;
}
</style>

<style>
.no-select {
  user-select: none;
}
</style>
