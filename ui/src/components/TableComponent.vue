<template>
  <div
    class="flex-1 min-w-full overflow-x-auto border border-gray-200 rounded bg-white"
  >
    <table class="min-w-full table-auto">
      <thead class="bg-gray-100 text-left text-sm font-semibold text-gray-700">
        <tr>
          <slot name="header" />
        </tr>
      </thead>
      <tbody class="text-sm text-gray-700 divide-y divide-gray-200">
        <slot name="body" />
      </tbody>
    </table>
  </div>
</template>
