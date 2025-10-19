<template>
  <LayoutComponent :links="sidebarLinks">
    <div class="flex items-center gap-2">
      <h1 class="text-2xl font-semibold">Enrollments</h1>
      <button
        @click="reloadEnrollments(undefined, true)"
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

    <TableComponent v-if="enrollments.length">
      <template #header>
        <th class="px-4 py-3">ID</th>
        <th class="px-4 py-3">Status</th>
        <th class="px-4 py-3">Created At</th>
        <th class="px-4 py-3">Expires At</th>
        <th class="px-4 py-3">Client ID</th>
      </template>

      <template #body>
        <tr
          v-for="enrollment in enrollments"
          :key="enrollment.enrollmentId"
          class="hover:bg-gray-50 cursor-pointer"
          @click="selectEnrollment(enrollment)"
        >
          <td class="px-4 py-2 font-mono truncate">
            {{ enrollment.enrollmentId }}
          </td>
          <td class="px-4 py-2 truncate">{{ enrollment.status }}</td>
          <td class="px-4 py-2 truncate">{{ enrollment.creationDateTime }}</td>
          <td class="px-4 py-2 truncate">
            {{ enrollment.expirationDateTime || "—" }}
          </td>
          <td class="px-4 py-2 truncate">{{ enrollment.clientId }}</td>
        </tr>
      </template>
    </TableComponent>
    <div v-else class="flex-1 flex items-center justify-center">
      <p class="text-gray-500">No enrollments found.</p>
    </div>
    <PaginationComponent
      :hasPrev="!!paginationLinks.prev"
      :hasNext="!!paginationLinks.next"
      :show="enrollments.length > 0"
      @prev="reloadEnrollments(paginationLinks.prev)"
      @next="reloadEnrollments(paginationLinks.next)"
    />

    <transition name="slide-left">
      <SidePanelComponent
        v-if="selectedEnrollment"
        :title="'Enrollment Details'"
        @close="selectedEnrollment = null"
      >
        <div class="flex flex-col h-full space-y-4 overflow-y-auto">
          <div>
            <div class="text-gray-500 text-xs uppercase">ID</div>
            <div class="font-mono text-sm text-gray-800">
              {{ selectedEnrollment?.enrollmentId }}
            </div>
          </div>

          <div>
            <div class="text-gray-500 text-xs uppercase">Status</div>
            <div class="text-gray-800">{{ selectedEnrollment?.status }}</div>
          </div>

          <div>
            <div class="text-gray-500 text-xs uppercase">Created At</div>
            <div class="text-gray-800">
              {{ selectedEnrollment?.creationDateTime }}
            </div>
          </div>

          <div>
            <div class="text-gray-500 text-xs uppercase">Status Update At</div>
            <div class="text-gray-800">
              {{ selectedEnrollment?.creationDateTime }}
            </div>
          </div>

          <div>
            <div class="text-gray-500 text-xs uppercase">Expires At</div>
            <div class="text-gray-800">
              {{ selectedEnrollment?.expirationDateTime || "—" }}
            </div>
          </div>

          <div>
            <div class="text-gray-500 text-xs uppercase">Client ID</div>
            <div class="text-gray-800">{{ selectedEnrollment?.clientId }}</div>
          </div>

          <div>
            <div class="text-gray-500 text-xs uppercase">User ID</div>
            <div class="text-gray-800">{{ selectedEnrollment?.userId }}</div>
          </div>

          <div>
            <div class="text-gray-500 text-xs uppercase">Permissions</div>
            <div
              class="bg-gray-50 border border-gray-200 rounded p-2 max-h-40 overflow-y-auto space-y-1 text-gray-800 text-sm"
            >
              <div
                v-for="(perm, index) in selectedEnrollment?.permissions"
                :key="index"
                class="font-mono"
              >
                {{ perm }}
              </div>
            </div>
          </div>
        </div>
      </SidePanelComponent>
    </transition>
  </LayoutComponent>
</template>

<script setup lang="ts">
import { ref, onMounted } from "vue";
import { useRoute } from "vue-router";
import { useToast } from "vue-toastification";
import { ArrowPathIcon } from "@heroicons/vue/24/solid";
import LayoutComponent from "../components/LayoutComponent.vue";
import SidePanelComponent from "../components/SidePanelComponent.vue";
import TableComponent from "../components/TableComponent.vue";
import type { Enrollment, Links } from "../types";
import { fetchEnrollments } from "../utils";
import PaginationComponent from "../components/PaginationComponent.vue";

const route = useRoute();
const toast = useToast();
const enrollments = ref<Enrollment[]>([]);
const selectedEnrollment = ref<Enrollment | null>(null);
const paginationLinks = ref<Links>({});

const orgId = route.params.orgId as string;
const userId = route.params.userId as string;
const isReloading = ref(false);
const sidebarLinks = [
  { label: "Accounts", path: `/orgs/${orgId}/users/${userId}/accounts` },
  { label: "Consents", path: `/orgs/${orgId}/users/${userId}/consents` },
  { label: "Resources", path: `/orgs/${orgId}/users/${userId}/resources` },
  { label: "Enrollments", path: `/orgs/${orgId}/users/${userId}/enrollments` },
];

const selectEnrollment = (enrollment: Enrollment) => {
  selectedEnrollment.value = enrollment;
};

const reloadEnrollments = async (url?: string, notify?: boolean) => {
  url = paginationLinks.value.self ?? url;
  isReloading.value = true;
  try {
    const { data, links } = await fetchEnrollments(userId, orgId, url);
    enrollments.value = data;
    paginationLinks.value = links;
    if (notify) toast.info("Enrollments reloaded");
  } finally {
    isReloading.value = false;
  }
};

onMounted(reloadEnrollments);
</script>
