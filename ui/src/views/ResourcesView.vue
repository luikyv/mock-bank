<template>
  <LayoutComponent :links="sidebarLinks">
    <div class="flex items-center gap-2">
      <h1 class="text-2xl font-semibold">Shared Resources</h1>
      <button
        @click="reloadResources(undefined, true)"
        class="p-1 rounded-full hover:bg-gray-100 text-gray-500 hover:text-gray-700 transition"
        :disabled="isReloading"
        title="Reload users"
      >
        <ArrowPathIcon
          class="h-5 w-5"
          :class="{ 'animate-spin': isReloading }"
        />
      </button>
    </div>

    <TableComponent v-if="resources.length">
      <template #header>
        <th class="px-4 py-3">Resource ID</th>
        <th class="px-4 py-3">Consent ID</th>
        <th class="px-4 py-3">Status</th>
        <th class="px-4 py-3">Type</th>
        <th class="px-4 py-3">Created At</th>
      </template>

      <template #body>
        <tr
          v-for="resource in resources"
          :key="resource.resourceId + resource.consentId"
          class="hover:bg-gray-50 cursor-pointer"
          @click="selectResource(resource)"
        >
          <td class="px-4 py-2 font-mono truncate">
            {{ resource.resourceId }}
          </td>
          <td class="px-4 py-2 font-mono truncate">
            {{ resource.consentId }}
          </td>
          <td class="px-4 py-2 truncate">{{ resource.status }}</td>
          <td class="px-4 py-2 truncate">{{ resource.type }}</td>
          <td class="px-4 py-2 truncate">{{ resource.creationDateTime }}</td>
        </tr>
      </template>
    </TableComponent>
    <div v-else class="flex-1 flex items-center justify-center">
      <p class="text-gray-500">No resources found.</p>
    </div>
    <PaginationComponent
      :hasPrev="!!paginationLinks.prev"
      :hasNext="!!paginationLinks.next"
      :show="resources.length > 0"
      @prev="reloadResources(paginationLinks.prev)"
      @next="reloadResources(paginationLinks.next)"
    />

    <transition name="slide-left">
      <SidePanelComponent
        v-if="selectedResource"
        :title="'Resource Details'"
        @close="selectedResource = null"
      >
        <div class="flex flex-col h-full space-y-4 overflow-y-auto">
          <div>
            <div class="text-gray-500 text-xs uppercase">Resource ID</div>
            <div class="font-mono text-sm text-gray-800">
              {{ selectedResource?.resourceId }}
            </div>
          </div>

          <div>
            <div class="text-gray-500 text-xs uppercase">Consent ID</div>
            <div class="font-mono text-sm text-gray-800">
              {{ selectedResource?.consentId }}
            </div>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1"
              >Status</label
            >
            <select
              v-model="selectedResource.status"
              class="w-full border border-gray-300 rounded px-3 py-2 text-sm"
              required
            >
              <option
                v-for="value in ResourceStatus"
                :key="value"
                :value="value"
              >
                {{ value }}
              </option>
            </select>
          </div>

          <div>
            <div class="text-gray-500 text-xs uppercase">Type</div>
            <div class="text-gray-800">
              {{ selectedResource?.type }}
            </div>
          </div>

          <div>
            <div class="text-gray-500 text-xs uppercase">Created At</div>
            <div class="text-gray-800">
              {{ selectedResource?.creationDateTime }}
            </div>
          </div>
        </div>

        <template #panel-actions>
          <button
            @click="saveResource"
            :disabled="!resourceWasEdited"
            :class="[
              'text-white text-sm font-medium py-2 px-4 rounded',
              resourceWasEdited
                ? 'bg-blue-600 hover:bg-blue-700'
                : 'bg-gray-300 cursor-not-allowed',
            ]"
          >
            Save
          </button>
        </template>
      </SidePanelComponent>
    </transition>
  </LayoutComponent>
</template>

<script setup lang="ts">
import { ref, onMounted, computed, watch } from "vue";
import { useRoute } from "vue-router";
import { ArrowPathIcon } from "@heroicons/vue/24/solid";
import LayoutComponent from "../components/LayoutComponent.vue";
import SidePanelComponent from "../components/SidePanelComponent.vue";
import TableComponent from "../components/TableComponent.vue";
import { ResourceStatus, type Links, type Resource } from "../types";
import { fetchMockResources, updateMockResource } from "../utils";
import { useToast } from "vue-toastification";
import PaginationComponent from "../components/PaginationComponent.vue";

const route = useRoute();
const toast = useToast();

const orgId = route.params.orgId as string;
const userId = route.params.userId as string;
const isReloading = ref(false);
const sidebarLinks = [
  { label: "Accounts", path: `/orgs/${orgId}/users/${userId}/accounts` },
  { label: "Consents", path: `/orgs/${orgId}/users/${userId}/consents` },
  { label: "Resources", path: `/orgs/${orgId}/users/${userId}/resources` },
  { label: "Enrollments", path: `/orgs/${orgId}/users/${userId}/enrollments` },
];

const resources = ref<Resource[]>([]);
const selectedResource = ref<Resource | null>(null);
const originalResource = ref<Resource | null>(null);
const paginationLinks = ref<Links>({});

watch(
  () => selectedResource.value,
  (resource) => {
    originalResource.value = resource ? { ...resource } : null;
  },
  { immediate: true }
);

const resourceWasEdited = computed(() => {
  if (!selectedResource.value || !originalResource.value) return false;
  return selectedResource.value.status !== originalResource.value.status;
});

const selectResource = (resource: Resource) => {
  selectedResource.value = { ...resource };
};

const saveResource = async () => {
  if (!selectedResource.value) return;
  await updateMockResource(userId, orgId, selectedResource.value);
  await reloadResources();
  selectedResource.value = null;
  toast.success("Shared resource updated successfully!");
};

const reloadResources = async (url?: string, notify?: boolean) => {
  url = paginationLinks.value.self ?? url;
  isReloading.value = true;
  try {
    const { data, links } = await fetchMockResources(userId, orgId, url);
    resources.value = data;
    paginationLinks.value = links;
    if (notify) toast.info("Resources reloaded");
  } finally {
    isReloading.value = false;
  }
};

onMounted(reloadResources);
</script>
