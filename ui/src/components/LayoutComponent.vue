<template>
  <div class="min-h-screen flex">
    <!-- Side Bar -->
    <aside
      class="w-[12vw] min-w-[200px] max-w-[300px] bg-[#497E94] text-white flex flex-col p-6 space-y-6"
    >
      <div>
        <h2 class="text-xl font-bold mb-1">MockBank</h2>
      </div>
      <nav class="space-y-2">
        <router-link
          v-for="link in links"
          :key="link.path"
          :to="link.path"
          class="block px-3 py-2 rounded hover:bg-[#3F3F3F] transition"
          active-class="bg-[#3F3F3F]"
        >
          {{ link.label }}
        </router-link>
      </nav>
    </aside>

    <!-- Main content -->
    <main class="flex-1 bg-gray-100 overflow-x-hidden">
      <!-- Breadcrumb -->
      <div
        class="bg-white border-b border-gray-300 px-6 py-3 flex items-center space-x-3"
      >
        <template v-if="org">
          <div class="flex items-center space-x-1">
            <span class="font-medium text-gray-800">{{ org.name }}</span>
            <button
              @click="clearOrg"
              class="text-[#497E94] text-xl leading-none hover:opacity-80 transition"
              title="Clear organization"
            >
              ×
            </button>
          </div>
        </template>

        <template v-if="mockUser && org">
          <div class="flex items-center space-x-1">
            <span class="font-medium text-gray-800">{{ mockUser.name }}</span>
            <button
              @click="clearMockUser"
              class="text-[#497E94] text-xl leading-none hover:opacity-80 transition"
              title="Clear user"
            >
              ×
            </button>
          </div>
        </template>
      </div>

      <div class="p-6 min-h-[calc(100vh-56px)]">
        <slot />
      </div>
    </main>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { useRouter } from "vue-router";
import { useStore } from "../stores";

defineProps<{
  links?: { label: string; path: string }[];
}>();

const router = useRouter();
const store = useStore();
const org = computed(() => store.org);
const mockUser = computed(() => store.mockUser);

const clearOrg = () => {
  store.org = null;
  store.mockUser = null;
  router.push("/orgs");
};

const clearMockUser = () => {
  store.mockUser = null;
  router.push(`/orgs/${org.value?.id}/users`);
};
</script>
