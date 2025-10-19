<template>
  <LayoutComponent :links="sidebarLinks">
    <div class="flex justify-between items-center mb-6">
      <div class="flex items-center gap-2">
        <h1 class="text-2xl font-semibold">Accounts</h1>
        <button
          @click="reloadAccounts(undefined, true)"
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
        @click="
          newAccount = {
            number: '',
            type: AccountType.CHECKING,
            subtype: AccountSubtype.INDIVIDUAL,
            availableAmount: '0.00',
            blockedAmount: '0.00',
            automaticallyInvestedAmount: '0.00',
          }
        "
      >
        Create Account
      </button>
    </div>

    <TableComponent v-if="accounts.length">
      <template #header>
        <th class="px-4 py-3">ID</th>
        <th class="px-4 py-3">Number</th>
        <th class="px-4 py-3">Branch</th>
        <th class="px-4 py-3">Digit</th>
        <th class="px-4 py-3">Type</th>
        <th class="px-4 py-3">Subtype</th>
      </template>

      <template #body>
        <tr
          v-for="account in accounts"
          :key="account.accountId"
          class="hover:bg-gray-50 cursor-pointer"
          @click="selectAccount(account)"
        >
          <td class="px-4 py-2 font-mono truncate">
            {{ account.accountId }}
          </td>
          <td class="px-4 py-2 truncate">{{ account.number }}</td>
          <td class="px-4 py-2 truncate">{{ account.branchCode || "-" }}</td>
          <td class="px-4 py-2 truncate">{{ account.checkDigit || "-" }}</td>
          <td class="px-4 py-2 truncate">{{ account.type }}</td>
          <td class="px-4 py-2 truncate">{{ account.subtype }}</td>
        </tr>
      </template>
    </TableComponent>
    <div v-else class="flex-1 flex items-center justify-center">
      <p class="text-gray-500">No accounts found.</p>
    </div>
    <PaginationComponent
      :hasPrev="!!paginationLinks.prev"
      :hasNext="!!paginationLinks.next"
      :show="accounts.length > 0"
      @prev="reloadAccounts(paginationLinks.prev)"
      @next="reloadAccounts(paginationLinks.next)"
    />

    <transition name="slide-left">
      <SidePanelComponent
        v-if="newAccount"
        title="Create New Account"
        @close="newAccount = null"
      >
        <template #panel-actions>
          <button
            type="submit"
            form="create-account-form"
            :disabled="!newAccountIsValid"
            :class="[
              'text-white text-sm font-medium py-2 px-4 rounded',
              newAccountIsValid
                ? 'bg-blue-600 hover:bg-blue-700'
                : 'bg-gray-300 cursor-not-allowed',
            ]"
          >
            Create
          </button>
        </template>

        <form id="create-account-form" @submit.prevent="createAccount">
          <div class="space-y-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1"
                >Number</label
              >
              <input
                v-model="newAccount.number"
                type="text"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"
                :class="{
                  'border-red-500':
                    newAccount.number && !newAccountNumberIsValid,
                }"
                required
              />
              <p
                v-if="newAccount.number && !newAccountNumberIsValid"
                class="text-red-500 text-xs mt-1"
              >
                Number must contain between 8 and 10 numeric digits.
              </p>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1"
                >Type</label
              >
              <select
                v-model="newAccount.type"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"
                required
              >
                <option
                  v-for="value in AccountType"
                  :key="value"
                  :value="value"
                >
                  {{ value }}
                </option>
              </select>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1"
                >Subtype</label
              >
              <select
                v-model="newAccount.subtype"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"
                required
              >
                <option
                  v-for="value in AccountSubtype"
                  :key="value"
                  :value="value"
                >
                  {{ value }}
                </option>
              </select>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1"
                >Available Amount (R$)</label
              >
              <input
                v-model="newAccount.availableAmount"
                type="text"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"
                :class="{
                  'border-red-500':
                    newAccount.availableAmount &&
                    !newAccountAvailableAmountIsValid,
                }"
                required
              />
              <p
                v-if="
                  newAccount.availableAmount &&
                  !newAccountAvailableAmountIsValid
                "
                class="text-red-500 text-xs mt-1"
              >
                Invalid amount format.
              </p>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1"
                >Automatically Invested Amount (R$)</label
              >
              <input
                v-model="newAccount.automaticallyInvestedAmount"
                type="text"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"
                :class="{
                  'border-red-500':
                    newAccount.automaticallyInvestedAmount &&
                    !newAccountAutomaticallyInvestedAmountIsValid,
                }"
                required
              />
              <p
                v-if="
                  newAccount.automaticallyInvestedAmount &&
                  !newAccountAutomaticallyInvestedAmountIsValid
                "
                class="text-red-500 text-xs mt-1"
              >
                Invalid amount format.
              </p>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1"
                >Blocked Amount (R$)</label
              >
              <input
                v-model="newAccount.blockedAmount"
                type="text"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"
                :class="{
                  'border-red-500':
                    newAccount.blockedAmount && !newAccountBlockedAmountIsValid,
                }"
                required
              />
              <p
                v-if="
                  newAccount.blockedAmount && !newAccountBlockedAmountIsValid
                "
                class="text-red-500 text-xs mt-1"
              >
                Invalid amount format.
              </p>
            </div>
          </div>
        </form>
      </SidePanelComponent>
    </transition>

    <transition name="slide-left">
      <SidePanelComponent
        v-if="selectedAccount"
        :title="'Account Details'"
        @close="selectedAccount = null"
      >
        <div class="flex flex-col h-full space-y-4 overflow-y-auto">
          <div>
            <div class="text-gray-500 text-xs uppercase">ID</div>
            <div class="font-mono text-sm text-gray-800">
              {{ selectedAccount.accountId }}
            </div>
          </div>

          <div>
            <label class="text-gray-500 text-xs uppercase">Number</label>
            <input
              v-model="selectedAccount.number"
              type="text"
              class="w-full border border-gray-300 rounded px-3 py-2 text-sm"
              :class="{
                'border-red-500':
                  selectedAccount.number && !selectedAccountNumberIsValid,
              }"
              required
            />
            <p
              v-if="selectedAccount.number && !selectedAccountNumberIsValid"
              class="text-red-500 text-xs mt-1"
            >
              Number must contain between 8 and 10 numeric digits.
            </p>
          </div>

          <div>
            <div class="text-gray-500 text-xs uppercase">Branch Code</div>
            <div class="text-gray-800">
              {{ selectedAccount.branchCode || "-" }}
            </div>
          </div>

          <div>
            <div class="text-gray-500 text-xs uppercase">Check Digit</div>
            <div class="text-gray-800">{{ selectedAccount.checkDigit }}</div>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1"
              >Type</label
            >
            <select
              v-model="selectedAccount.type"
              class="w-full border border-gray-300 rounded px-3 py-2 text-sm"
              required
            >
              <option v-for="value in AccountType" :key="value" :value="value">
                {{ value }}
              </option>
            </select>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1"
              >Subtype</label
            >
            <select
              v-model="selectedAccount.subtype"
              class="w-full border border-gray-300 rounded px-3 py-2 text-sm"
              required
            >
              <option
                v-for="value in AccountSubtype"
                :key="value"
                :value="value"
              >
                {{ value }}
              </option>
            </select>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1"
              >Available Amount (R$)</label
            >
            <input
              v-model="selectedAccount.availableAmount"
              type="text"
              class="w-full border border-gray-300 rounded px-3 py-2 text-sm"
              :class="{
                'border-red-500':
                  selectedAccount.availableAmount &&
                  !selectedAccountAvailableAmountIsValid,
              }"
              required
            />
            <p
              v-if="
                selectedAccount.availableAmount &&
                !selectedAccountAvailableAmountIsValid
              "
              class="text-red-500 text-xs mt-1"
            >
              Invalid amount format.
            </p>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1"
              >Automatically Invested Amount (R$)</label
            >
            <input
              v-model="selectedAccount.automaticallyInvestedAmount"
              type="text"
              class="w-full border border-gray-300 rounded px-3 py-2 text-sm"
              :class="{
                'border-red-500':
                  selectedAccount.automaticallyInvestedAmount &&
                  !selectedAccountAutomaticallyInvestedAmountIsValid,
              }"
              required
            />
            <p
              v-if="
                selectedAccount.automaticallyInvestedAmount &&
                !selectedAccountAutomaticallyInvestedAmountIsValid
              "
              class="text-red-500 text-xs mt-1"
            >
              Invalid amount format.
            </p>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1"
              >Blocked Amount (R$)</label
            >
            <input
              v-model="selectedAccount.blockedAmount"
              type="text"
              class="w-full border border-gray-300 rounded px-3 py-2 text-sm"
              :class="{
                'border-red-500':
                  selectedAccount.blockedAmount &&
                  !selectedAccountBlockedAmountIsValid,
              }"
              required
            />
            <p
              v-if="
                selectedAccount.blockedAmount &&
                !selectedAccountBlockedAmountIsValid
              "
              class="text-red-500 text-xs mt-1"
            >
              Invalid amount format.
            </p>
          </div>
        </div>

        <template #panel-actions>
          <div class="flex justify-between items-center w-full">
            <button
              @click="saveAccount"
              :disabled="!accountWasEdited || !selectedAccountIsValid"
              :class="[
                'text-white text-sm font-medium py-2 px-4 rounded',
                accountWasEdited && selectedAccountIsValid
                  ? 'bg-blue-600 hover:bg-blue-700'
                  : 'bg-gray-300 cursor-not-allowed',
              ]"
            >
              Save
            </button>
            <button
              @click="deleteAccount"
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
import { ref, onMounted, computed, watch } from "vue";
import { useRoute } from "vue-router";
import { ArrowPathIcon } from "@heroicons/vue/24/solid";
import LayoutComponent from "../components/LayoutComponent.vue";
import SidePanelComponent from "../components/SidePanelComponent.vue";
import TableComponent from "../components/TableComponent.vue";
import { useToast } from "vue-toastification";
import {
  AccountSubtype,
  AccountType,
  type Account,
  type AccountRequest,
  type Links,
} from "../types";
import {
  createMockAccount,
  fetchMockAccounts,
  deleteMockAccount,
  updateMockAccount,
  isValidAccountNumber,
  isValidAmount,
} from "../utils";
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

const accounts = ref<Account[]>([]);
const selectedAccount = ref<Account | null>(null);
const originalAccount = ref<Account | null>(null);
const paginationLinks = ref<Links>({});

watch(
  () => selectedAccount.value,
  (account) => {
    originalAccount.value = account ? { ...account } : null;
  },
  { immediate: true }
);

const selectedAccountNumberIsValid = computed(() =>
  isValidAccountNumber(selectedAccount.value?.number ?? "")
);
const selectedAccountAvailableAmountIsValid = computed(() =>
  isValidAmount(selectedAccount.value?.availableAmount ?? "")
);
const selectedAccountAutomaticallyInvestedAmountIsValid = computed(() =>
  isValidAmount(selectedAccount.value?.automaticallyInvestedAmount ?? "")
);
const selectedAccountBlockedAmountIsValid = computed(() =>
  isValidAmount(selectedAccount.value?.blockedAmount ?? "")
);

const selectedAccountIsValid = computed(() => {
  return (
    selectedAccountNumberIsValid.value &&
    selectedAccountAvailableAmountIsValid.value &&
    selectedAccountAutomaticallyInvestedAmountIsValid.value &&
    selectedAccountBlockedAmountIsValid.value
  );
});

const accountWasEdited = computed(() => {
  if (!selectedAccount.value || !originalAccount.value) return false;
  return (
    selectedAccount.value.number !== originalAccount.value.number ||
    selectedAccount.value.availableAmount !==
      originalAccount.value.availableAmount ||
    selectedAccount.value.automaticallyInvestedAmount !==
      originalAccount.value.automaticallyInvestedAmount ||
    selectedAccount.value.blockedAmount !== originalAccount.value.blockedAmount
  );
});

const newAccount = ref<AccountRequest | null>(null);

const newAccountNumberIsValid = computed(() =>
  isValidAccountNumber(newAccount.value?.number ?? "")
);
const newAccountAvailableAmountIsValid = computed(() =>
  isValidAmount(newAccount.value?.availableAmount ?? "")
);
const newAccountAutomaticallyInvestedAmountIsValid = computed(() =>
  isValidAmount(newAccount.value?.automaticallyInvestedAmount ?? "")
);
const newAccountBlockedAmountIsValid = computed(() =>
  isValidAmount(newAccount.value?.blockedAmount ?? "")
);

const newAccountIsValid = computed(() => {
  return (
    newAccountNumberIsValid.value &&
    newAccountAvailableAmountIsValid.value &&
    newAccountAutomaticallyInvestedAmountIsValid.value &&
    newAccountBlockedAmountIsValid.value
  );
});

const selectAccount = (account: Account) => {
  selectedAccount.value = { ...account };
};

const createAccount = async () => {
  if (!newAccount.value) return;

  if (!newAccountIsValid.value) {
    toast.warning("Invalid input, form not submitted");
    return;
  }

  await createMockAccount(newAccount.value, userId, orgId);
  await reloadAccounts();
  newAccount.value = null;
  toast.success("Account created successfully!");
};

const saveAccount = async () => {
  if (!selectedAccount.value) return;

  if (!selectedAccountIsValid.value) {
    toast.warning("Invalid input, form not submitted");
    return;
  }

  await updateMockAccount(
    selectedAccount.value.accountId,
    userId,
    orgId,
    selectedAccount.value
  );
  await reloadAccounts();
  selectedAccount.value = null;
  toast.success("Account updated successfully!");
};

const deleteAccount = async () => {
  if (!selectedAccount.value) return;

  await deleteMockAccount(selectedAccount.value.accountId, userId, orgId);
  await reloadAccounts();
  selectedAccount.value = null;
  toast.success("Account deleted successfully!");
};

const reloadAccounts = async (url?: string, notify?: boolean) => {
  url = paginationLinks.value.self ?? url;
  isReloading.value = true;
  try {
    const { data, links } = await fetchMockAccounts(userId, orgId, url);
    accounts.value = data;
    paginationLinks.value = links;
    if (notify) toast.info("Accounts reloaded");
  } finally {
    isReloading.value = false;
  }
};

onMounted(reloadAccounts);
</script>
