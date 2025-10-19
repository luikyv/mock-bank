<template>
  <LayoutComponent :links="sidebarLinks">
    <div class="flex justify-between items-center mb-6">
      <div class="flex items-center gap-2">
        <h1 class="text-2xl font-semibold">Users</h1>
        <button
          @click="reloadUsers(undefined, true)"
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
      <button
        class="bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium py-2 px-4 rounded"
        @click="newUser = { username: '', cpf: '', name: '' }"
      >
        New User
      </button>
    </div>

    <div v-if="users.length" class="space-y-4">
      <RowComponent
        v-for="user in users"
        :key="user.id"
        :title="user.username"
        :onClick="() => selectUser(user)"
        :tags="[{ key: 'ID', value: user.id }]"
      ></RowComponent>
    </div>
    <div v-else class="text-gray-500">No users found.</div>

    <PaginationComponent
      :hasPrev="!!paginationLinks.prev"
      :hasNext="!!paginationLinks.next"
      :show="users.length > 0"
      @prev="reloadUsers(paginationLinks.prev)"
      @next="reloadUsers(paginationLinks.next)"
    />

    <transition name="slide-left">
      <SidePanelComponent
        v-if="newUser"
        title="Create New User"
        @close="newUser = null"
      >
        <template #panel-actions>
          <button
            type="submit"
            form="create-user-form"
            :disabled="!newUserIsValid"
            :class="[
              'text-white text-sm font-medium py-2 px-4 rounded',
              newUserIsValid
                ? 'bg-blue-600 hover:bg-blue-700'
                : 'bg-gray-300 cursor-not-allowed',
            ]"
          >
            Create
          </button>
        </template>

        <form id="create-user-form" @submit.prevent="createUser">
          <div class="space-y-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1"
                >Name</label
              >
              <input
                v-model="newUser.name"
                type="text"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"
                required
              />
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1"
                >Username</label
              >
              <input
                v-model="newUser.username"
                type="text"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"
                required
              />
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1"
                >CPF</label
              >
              <input
                v-model="newUser.cpf"
                type="text"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"
                :class="{ 'border-red-500': newUser.cpf && !newUserCpfIsValid }"
                required
              />
              <p
                v-if="newUser.cpf && !newUserCpfIsValid"
                class="text-red-500 text-xs mt-1"
              >
                CPF must contain 11 numeric digits.
              </p>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1"
                >Description</label
              >
              <textarea
                v-model="newUser.description"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"
                rows="3"
              ></textarea>
            </div>
          </div>
        </form>
      </SidePanelComponent>
    </transition>

    <transition name="slide-left">
      <SidePanelComponent
        v-if="selectedUser"
        title="User Details"
        @close="selectedUser = null"
      >
        <div class="flex flex-col h-full space-y-4 overflow-y-auto">
          <div>
            <div class="text-gray-500 text-xs uppercase">ID</div>
            <div class="font-mono text-sm text-gray-800">
              {{ selectedUser.id }}
            </div>
          </div>

          <div>
            <label class="text-gray-500 text-xs uppercase">Name</label>
            <input
              v-model="selectedUser.name"
              type="text"
              class="w-full border border-gray-300 rounded px-3 py-2 text-sm text-gray-800"
            />
          </div>

          <div>
            <label class="text-gray-500 text-xs uppercase">Username</label>
            <input
              v-model="selectedUser.username"
              type="text"
              class="w-full border border-gray-300 rounded px-3 py-2 text-sm text-gray-800"
            />
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1"
              >CPF</label
            >
            <input
              v-model="selectedUser.cpf"
              type="text"
              class="w-full border border-gray-300 rounded px-3 py-2 text-sm"
              :class="{
                'border-red-500': selectedUser.cpf && !selectedUserCpfIsValid,
              }"
              required
            />
            <p
              v-if="selectedUser.cpf && !selectedUserCpfIsValid"
              class="text-red-500 text-xs mt-1"
            >
              CPF must contain 11 numeric digits.
            </p>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1"
              >CNPJ</label
            >
            <input
              v-model="selectedUser.cnpj"
              type="text"
              class="w-full border border-gray-300 rounded px-3 py-2 text-sm"
              :class="{ 'border-red-500': selectedUser.cnpj && !selectedUserCnpjIsValid }"
            />
            <p
              v-if="selectedUser.cnpj && !selectedUserCnpjIsValid"
              class="text-red-500 text-xs mt-1"
            >
              CNPJ must contain 14 numeric digits.
            </p>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1"
              >Description</label
            >
            <textarea
              v-model="selectedUser.description"
              class="w-full border border-gray-300 rounded px-3 py-2 text-sm"
              rows="4"
            ></textarea>
          </div>
        </div>

        <template #panel-actions>
          <div class="flex justify-between items-center w-full">
            <div class="flex gap-2">
              <button
                @click="saveUser"
                :disabled="!userWasEdited || !selectedUserIsValid"
                :class="[
                  'text-white text-sm font-medium py-2 px-4 rounded',
                  userWasEdited
                    ? 'bg-blue-600 hover:bg-blue-700'
                    : 'bg-gray-300 cursor-not-allowed',
                ]"
              >
                Save
              </button>
              <button
                @click="goToUserResources(selectedUser)"
                class="bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium py-2 px-4 rounded"
              >
                Go To Resources
              </button>
            </div>
            <button
              @click="deleteUser(selectedUser)"
              class="bg-red-600 hover:bg-red-700 text-white text-sm font-medium py-2 px-4 rounded"
            >
              Delete
            </button>
          </div>
        </template>
      </SidePanelComponent>
    </transition>
  </LayoutComponent>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from "vue";
import { useRoute, useRouter } from "vue-router";
import LayoutComponent from "../components/LayoutComponent.vue";
import RowComponent from "../components/RowComponent.vue";
import SidePanelComponent from "../components/SidePanelComponent.vue";
import { ArrowPathIcon } from "@heroicons/vue/24/solid";
import { useToast } from "vue-toastification";
import type { Links, MockUser, MockUserRequest } from "../types";
import {
  fetchMockUsers,
  createMockUser,
  updateMockUser,
  deleteMockUser,
  isValidCpf,
  isValidCnpj,
} from "../utils";
import { useStore } from "../stores";
import PaginationComponent from "../components/PaginationComponent.vue";

const route = useRoute();
const router = useRouter();
const toast = useToast();
const store = useStore();

const orgId = route.params.orgId as string;
const sidebarLinks = [{ label: "Users", path: `/orgs/${orgId}/users` }];
const isReloading = ref(false);

const users = ref<MockUser[]>([]);
const newUser = ref<MockUserRequest | null>(null);
const selectedUser = ref<MockUser | null>(null);
const originalUser = ref<MockUser | null>(null);
const paginationLinks = ref<Links>({});

const newUserCpfIsValid = computed(() =>
  isValidCpf(newUser.value?.cpf ?? "")
);
const newUserCnpjIsValid = computed(() =>
  !newUser.value?.cnpj || isValidCnpj(newUser.value.cnpj)
);
const newUserIsValid = computed(
  () => newUser.value !== null && newUserCpfIsValid.value && newUserCnpjIsValid.value
);

const selectedUserCpfIsValid = computed(() =>
  isValidCpf(selectedUser.value?.cpf ?? "")
);
const selectedUserCnpjIsValid = computed(() =>
  !selectedUser.value?.cnpj || isValidCnpj(selectedUser.value.cnpj)
);
const selectedUserIsValid = computed(
  () =>
    selectedUser.value !== null &&
    selectedUserCpfIsValid.value &&
    selectedUserCnpjIsValid.value
);

const userWasEdited = computed(() => {
  if (!selectedUser.value || !originalUser.value) return false;
  return (
    selectedUser.value.name !== originalUser.value.name ||
    selectedUser.value.username !== originalUser.value.username ||
    selectedUser.value.cpf !== originalUser.value.cpf ||
    selectedUser.value.cnpj !== originalUser.value.cnpj ||
    selectedUser.value.description !== originalUser.value.description
  );
});

const selectUser = (user: MockUser) => {
  selectedUser.value = { ...user };
  originalUser.value = { ...user };
};

const createUser = async () => {
  if (!newUser.value || !newUserIsValid.value) return;
  await createMockUser(newUser.value, orgId);
  await reloadUsers();
  newUser.value = null;
  toast.success("User created successfully!");
};

const saveUser = async () => {
  if (!selectedUser.value || !selectedUserIsValid.value) return;
  await updateMockUser(selectedUser.value.id, selectedUser.value, orgId);
  await reloadUsers();
  selectedUser.value = null;
  toast.success("User updated successfully!");
};

const deleteUser = async (user: MockUser) => {
  await deleteMockUser(user.id, orgId);
  await reloadUsers();
  if (selectedUser.value?.id === user.id) selectedUser.value = null;
  toast.success("User deleted successfully!");
};

const goToUserResources = (user: MockUser) => {
  store.mockUser = user;
  router.push(`/orgs/${orgId}/users/${user.id}`);
};

const reloadUsers = async (url?: string, notify?: boolean) => {
  url = paginationLinks.value.self ?? url;
  isReloading.value = true;
  try {
    const { data, links } = await fetchMockUsers(orgId, url);
    users.value = data;
    paginationLinks.value = links;
    if (notify) toast.info("Users reloaded");
  } finally {
    isReloading.value = false;
  }
};

onMounted(async () => {
  await reloadUsers();
});
</script>
