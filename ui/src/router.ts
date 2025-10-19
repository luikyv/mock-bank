import { createRouter, createWebHistory } from "vue-router";
import type { RouteRecordRaw } from "vue-router";
import OrganizationsView from "./views/OrganizationsView.vue";
import UsersView from "./views/UsersView.vue";
import ConsentsView from "./views/ConsentsView.vue";
import ResourcesView from "./views/ResourcesView.vue";
import AccountsView from "./views/AccountsView.vue";
import LoginView from "./views/LoginView.vue";
import EnrollmentsView from "./views/EnrollmentsView.vue";

const routes: RouteRecordRaw[] = [
  { path: "/", name: "Default", component: OrganizationsView },
  { path: "/orgs", name: "Organizations", component: OrganizationsView },
  { path: "/orgs/:orgId", name: "Organization", component: UsersView },
  { path: "/orgs/:orgId/users", name: "Users", component: UsersView },
  { path: "/orgs/:orgId/users/:userId", name: "User", component: AccountsView },
  { path: "/orgs/:orgId/users/:userId/consents", name: "ConsentsView", component: ConsentsView },
  { path: "/orgs/:orgId/users/:userId/resources", name: "ResourcesView", component: ResourcesView},
  { path: "/orgs/:orgId/users/:userId/enrollments", name: "EnrollmentsView", component: EnrollmentsView},
  { path: "/orgs/:orgId/users/:userId/accounts", name: "Accounts", component: AccountsView},
  { path: "/login", name: "Login", component: LoginView },
];

export default createRouter({
  history: createWebHistory(),
  routes,
});
