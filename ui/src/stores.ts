import { defineStore } from "pinia";
import type { Organization, MockUser } from "./types";

export const useStore = defineStore("store", {
  state: () => ({
    org: null as Organization | null,
    mockUser: null as MockUser | null,
  }),
  persist: true,
});
