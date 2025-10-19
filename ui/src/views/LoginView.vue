<template>
  <div class="min-h-screen flex items-center justify-center bg-gray-100">
    <div class="bg-white shadow-md rounded-lg p-10 w-full max-w-md text-center">
      <h1 class="text-2xl font-bold text-gray-800 mb-6">Welcome to MockBank</h1>
      <p class="text-gray-600 mb-8">Sign in using your Directory account</p>
      <button
        @click="directorySso"
        class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg transition duration-200"
      >
        Sign in with Directory
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { fetchAuthUrl } from "../utils";

async function directorySso() {
  const authUrl = await fetchAuthUrl();
  window.location.href = authUrl;
}
</script>
